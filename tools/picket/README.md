# PICKET — sensor box runbook

This is the operator runbook for the physical/VPS side of PICKET: the
honeypot sensor box itself. For the data contract, architecture, and how the
exported telemetry is consumed by the pipeline, see
[docs/PICKET.md](../../docs/PICKET.md). This document is about provisioning,
hardening, installing, verifying, rebuilding, and responding to an incident on
the box — read it start to finish before you touch a fresh VPS, because step 3
has a lock-out hazard.

## 1. What this box is

The sensor box runs [knock-knock](https://github.com/djkurlander/knock-knock)
(MIT-licensed honeypot) listening on common attacker-facing ports (SSH,
Telnet, FTP, SMTP, HTTP, SMB, RDP, SIP) and nothing else of value. **Treat it
as bait: assume it gets compromised.** It holds no production data, no
production credentials, and no access back into SOCDesk's real infrastructure
— it is a standalone VPS whose only outbound relationship to the rest of the
system is a git push of an aggregated, fenced `export.json` to a
public, data-only repository. If the box is fully owned by an attacker, the
blast radius is: this box, and — until the deploy key is rotated — the
ability to push garbage commits to that one data repo. It is never able to
reach `data/state/`, the SOCDesk pipeline, or socdesk.io directly. The
pipeline's schema gate and last-known-good fallback (see
[docs/PICKET.md](../../docs/PICKET.md) and
[docs/OPERATIONS.md](../../docs/OPERATIONS.md)) mean even a vandalized export
cannot corrupt what the site publishes.

## 2. Provision

Pick a small VPS with a public IPv4 you don't mind being scanned constantly —
this is intentional attack-surface, not a shared box:

- **Hetzner CX22** (or similar small x86 instance), or **Oracle Cloud's
  Always Free ARM** (Ampere A1) instance.
- OS image: **Debian 12** or **Ubuntu 24.04**. `install.sh` targets these two.
- Note the box's public IP — you'll need it repeatedly below.
- Add your admin SSH public key at provisioning time (cloud-init /
  provider's "SSH keys" step), so you never type a root password over the
  network:

```
ssh-copy-id root@<ip>          # only if the provider didn't seed your key
ssh root@<ip>
```

## 3. Harden, in order

`install.sh` is idempotent but **step 2 changes your SSH port and disables
password auth — if you get this wrong and disconnect, you are locked out**
(cloud console / rescue mode is your only way back in). Do not skip the
verification pause. Run it **interactively** (it pauses with `read`; a
non-TTY stdin aborts it under `set -e`).

**Before running `install.sh`:** stage the exporter files on the box — the
script's own step 6 runs
`pip install -q -r /opt/socdesk/tools/picket/requirements.txt`, which requires
those files to already be present at `/opt/socdesk/tools/picket/` (the script
checks and stops with a clear message if they are not). Run §5
"Exporter"'s copy block now, from your workstation, **using port 22** (at this
point in the process the real sshd hasn't moved yet — that only happens a few
lines below, once you run `install.sh` itself). Come back here once the copy
is done and verified.

Set the environment variables and run the script as root on the fresh box.
The script's header comment lists every variable it reads:

```bash
export ADMIN_SSH_PORT=2222                    # optional, defaults to 2222
export ADMIN_USER=root                        # optional, defaults to root — the ONE account sshd will admit (AllowUsers)
export ADMIN_ALLOW_CIDR=203.0.113.9/32        # REQUIRED: your admin source IP/CIDR
export KK_TAG=v3.0.0                          # REQUIRED: pinned knock-knock release tag — list them first: git ls-remote --tags https://github.com/djkurlander/knock-knock.git
export EXPORT_REPO=git@github.com:SaltyCarl/socdesk-picket-export.git          # optional (default): SSH push URL, used with the deploy key
export EXPORT_REPO_HTTPS=https://github.com/SaltyCarl/socdesk-picket-export.git # optional (default): keyless read-only clone URL
export MAXMIND_ACCOUNT_ID=<id>                # optional pair (§4): set both and the script writes knock-knock's .env
export MAXMIND_LICENSE_KEY=<key>              #   AND /etc/GeoIP.conf and fetches GeoLite2-Country; unset -> country omitted
bash /opt/socdesk/tools/picket/install.sh
```

The script installs packages **first** (step 1 — Docker from Docker's own apt
repo on both target OSes, `sudo`, `ufw`, `acl`, `unattended-upgrades`,
`geoipupdate`), so a package failure can never strand a half-hardened box.
Step 2 then writes `/etc/ssh/sshd_config.d/00-picket.conf` — `Port
ADMIN_SSH_PORT`, `PasswordAuthentication no`, `KbdInteractiveAuthentication
no`, `PermitRootLogin prohibit-password`, `AllowUsers ADMIN_USER` — as a
drop-in rather than editing `sshd_config`: sshd keeps the first value it reads
for each keyword and the `Include sshd_config.d/*.conf` comes first, so
`00-picket.conf` wins over both `sshd_config` and any provider cloud-init
drop-in (`50-cloud-init.conf: PasswordAuthentication yes` is common). On
Ubuntu 24.04 sshd is socket-activated and `Port` would be ignored, so the
script disables `ssh.socket` and enables `ssh.service` instead. It then prints
the **effective** configuration and **stops at a prompt**:

```
>> EFFECTIVE sshd config (sshd -T) — this is what is actually enforced:
port 2222
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin prohibit-password
allowusers root
```

If those five lines do not read like that, do not press enter. Before
pressing enter:

```bash
# from a SECOND terminal, do not close the first
ssh -p 2222 root@<ip>
```

Only press enter in the first terminal once that second connection succeeds.
If it fails, fix `/etc/ssh/sshd_config.d/00-picket.conf` from the still-open
first session, `sshd -t && systemctl restart ssh`, re-check `sshd -T` — do
not disconnect it.

After the script finishes (firewall + knock-knock + exporter steps), confirm
the box exposes only what it should, from an **external** machine (not the
box itself):

```bash
nmap -Pn -p- <ip>
```

Expected: the honeypot ports (21, 22, 23, 25, 80, 445, 3389/tcp, 5060/tcp+udp)
plus `ADMIN_SSH_PORT` (2222) — nothing else. Note that port 22 in this scan is
knock-knock's honeypot listener, not your real sshd (which is on
`ADMIN_SSH_PORT`).

## 4. knock-knock

`install.sh` clones the **pinned tag** (`KK_TAG`) — never `main` — so the
protocol IDs and `.env` shape stay stable between exporter runs. Do not
`git pull` inside `/opt/knock-knock` to "update"; re-provision with a new
`KK_TAG` instead.

**MaxMind (GeoLite2 free tier — see
[Attribution obligations](#9-attribution-obligations)).** Two separate
databases are in play, and they are provisioned differently:

- knock-knock's **own** `geoipupdate` container fetches GeoLite2-**City** and
  GeoLite2-**ASN** into a named Docker volume — that is where `lat`/`lng` and
  ISP names come from. It reads `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY`
  from `/opt/knock-knock/.env`.
- the **exporter's** per-IP `country` comes from a **host** copy of
  GeoLite2-**Country** at `/usr/share/GeoIP/GeoLite2-Country.mmdb`, fetched
  by the host `geoipupdate` package from `/etc/GeoIP.conf`. The container's
  volume is not visible to the exporter, and it is the wrong edition anyway.

The simplest path: export `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY`
**before** `install.sh` (§3) — the script writes both places and runs
`geoipupdate` once. If you add them later: edit `/opt/knock-knock/.env` and
then `cd /opt/knock-knock && docker compose restart` (the container reads its
`.env` at start, not live), and write `/etc/GeoIP.conf` by hand:

```
AccountID <your account id>
LicenseKey <your license key>
EditionIDs GeoLite2-Country
DatabaseDirectory /usr/share/GeoIP
```

then `geoipupdate && systemctl enable --now geoipupdate.timer`. Until the
`.mmdb` exists and is readable by `picket`, the exporter still publishes — it
logs one line per run, `geoip: <reason> — publishing without country`, and
every `top_ips[]` row simply has no `country` key (spec §5, the optional
field). `lat`/`lng` from knock-knock's own City database are unaffected.

Sanity-check the containers came up clean:

```bash
cd /opt/knock-knock && docker compose logs -f
```

Confirm knock-knock is not writing per-knock rows (rollups only — this is
what makes the exporter's SQLite reads safe to publish from):

```bash
grep -n '^SAVE_KNOCKS' /opt/knock-knock/.env
```

Expected: the line is commented out (`# SAVE_KNOCKS off: rollups only`), not
`SAVE_KNOCKS=true`.

**Protocol set.** Confirm `install.sh` wrote the P1 protocol set:

```bash
grep -n '^ENABLED_PROTOCOLS' /opt/knock-knock/.env
```

Expected: `ENABLED_PROTOCOLS=SSH,TNET,FTP,RDP,SMB,SIP,HTTP,SMTP` — the spec's
P1 "core eight"; `TNET` is knock-knock's identifier for Telnet; knock-knock
also accepts `PROTO:PORT` entries such as `HTTP:80,HTTP:443`; the exporter
publishes exactly this set as `sensor.protocols`. The optional IoT/OT set
(`MQTT,NRED,MODB,S7,SNMP`) is a later owner toggle — do not enable in P1.

**Dashboard binding — two layers.** knock-knock `v3.0.0`'s
`docker-compose.host.yml` runs the dashboard as
`uvicorn ... --host ${WEB_LISTEN:-0.0.0.0}`; `.env.example` does not list the
variable, but the compose file honours it. `install.sh` writes
`WEB_LISTEN=127.0.0.1` (the first layer — the process itself only listens on
loopback) and makes sure `COMPOSE_FILE=docker-compose.host.yml` is set (host
networking, which is what puts port 8080 under ufw at all: under the bridge
`docker-compose.yml`, Docker publishes `8080:8080` through its own iptables
chain, which **bypasses ufw**). The §3 firewall — no rule for 8080 — is the
second layer. Check both, then prove it from outside:

```bash
grep -nE '^(WEB_LISTEN|COMPOSE_FILE)=' /opt/knock-knock/.env   # expected: WEB_LISTEN=127.0.0.1 and COMPOSE_FILE=docker-compose.host.yml
ss -ltnp | grep ':8080'                                        # expected: 127.0.0.1:8080, never 0.0.0.0:8080 or *:8080
curl -m 3 http://<ip>:8080          # from an EXTERNAL machine — must fail/timeout
```

To view it yourself, tunnel over SSH instead:

```bash
ssh -p 2222 -L 8080:127.0.0.1:8080 root@<ip>
# then open http://127.0.0.1:8080 locally
```

## 5. Exporter

If you haven't already (§3 tells you to do this *before* running
`install.sh`, since its step 6 pip-installs from these files), copy the
**entire** `tools/picket/` directory from this repo onto the box, under
`/opt/socdesk`, preserving paths — not just `exporter.py`, all of it, because
`exporter.py` imports the rest as `tools.picket.*`:

```
tools/picket/
  exporter.py
  assemble.py                          # assemble_export(), validate_export() — imported by exporter.py
  fence.py                             # fence_credential(), is_public_ip() — imported by assemble.py
  ring.py                              # apply_snapshot(), new_state() — imported by exporter.py
  __init__.py                          # makes tools.picket importable as a package
  requirements.txt
  systemd/
  install.sh
  README.md
collectors/base.py                     # clean_text(), iso() — assemble.py imports these
schemas/picket_export.schema.json      # the export schema validate_export() checks against
```

This is the **canonical copy block** — §3 also points here rather than
repeating it, so there's one command to keep correct, not two. Use `rsync`'s
relative mode (`-R` / `--relative`), which recreates each source path intact
under the destination instead of collapsing it to just its last component —
without `-R`, `tools/picket` would land at `/opt/socdesk/picket/` (dropping
the `tools/` segment), `collectors/base.py` at `/opt/socdesk/base.py`, and the
schema at `/opt/socdesk/picket_export.schema.json`, none of which match what
`exporter.py`'s imports or `SCHEMA = HERE.parent.parent / "schemas" / ...`
resolution expect:

```bash
# from your workstation, run from the repo root.
# SSH_PORT is 22 if you're doing this from §3, BEFORE install.sh has run (the
# real sshd hasn't moved yet); it's your ADMIN_SSH_PORT (2222 by default) if
# you're doing this from here, AFTER install.sh has already hardened the box
# (by then :22 is the knock-knock honeypot, not your real sshd).
SSH_PORT=22   # or your ADMIN_SSH_PORT, e.g. 2222, if running after install.sh
ssh -p "$SSH_PORT" root@<ip> mkdir -p /opt/socdesk
rsync -azR --exclude '__pycache__' -e "ssh -p $SSH_PORT" \
  tools/picket collectors/base.py schemas/picket_export.schema.json \
  root@<ip>:/opt/socdesk/
```

Verify the copy landed where the exporter expects before continuing — all
four paths must list:

```bash
ssh -p "$SSH_PORT" root@<ip> 'ls /opt/socdesk/tools/picket/requirements.txt /opt/socdesk/tools/picket/assemble.py /opt/socdesk/collectors/base.py /opt/socdesk/schemas/picket_export.schema.json'
```

`collectors/base.py` imports as `collectors.base`, so an empty package marker
must sit next to it — `install.sh` step 6 creates
`/opt/socdesk/collectors/__init__.py` if the copy did not bring one (nothing
in this repo's `collectors/__init__.py` is wanted on the box; it imports every
collector).

**The export repo.** `install.sh` clones it read-only over HTTPS (keyless — the
repo is public) and sets the **push** URL to SSH, so the clone always
succeeds on a fresh box and only the push needs the deploy key. Two
prerequisites on the GitHub side: the repo exists and is **non-empty**
(initialise it with a README so `main` exists — `git push` from the clone
tracks `origin/main`), and the deploy key below is registered.

**The deploy key** is generated by `install.sh` step 8, as the unprivileged
`picket` user, together with GitHub's host key in `known_hosts` and the git
identity (`picket <picket@socdesk.io>`). The script prints the public key at
the end; to see it again:

```bash
cat /var/lib/picket/.ssh/id_ed25519.pub
```

Add it at `github.com/SaltyCarl/socdesk-picket-export` → **Settings → Deploy
keys → Add deploy key** → paste → check **Allow write access**. Write-scoped,
on this one repo only — never a key with broader scope. Until it is
registered, every timer run ends in a `git push` error in
`journalctl -u picket-export`; that error is the signal, not a fault, and the
**first successful push is the confirmation** that the key is live.

**Pre-checks before the first run** — the exporter opens the database
read-only as `picket`, which needs three things to be true:

```bash
ls -l /opt/knock-knock/data/knock_knock.db*       # expected: knock_knock.db plus -wal and -shm once knock-knock has run
getfacl /opt/knock-knock/data/knock_knock.db | grep picket   # expected: user:picket:r--
sudo -Hu picket python3 -c "import sqlite3; print(sqlite3.connect('file:/opt/knock-knock/data/knock_knock.db?mode=ro', uri=True).execute('select count(*) from ip_intel').fetchone())"
```

The file is `knock_knock.db` — knock-knock v3.0.0's `monitor.py` builds the
path as `DB_DIR` (default `data`) + `/knock_knock.db`, mounted from
`./data:/app/data`; `DB_DIR` is the one upstream variable that could move it.
knock-knock opens it in **WAL** mode (`PRAGMA journal_mode=WAL`), so a reader
needs the `-wal` and `-shm` files to be readable too, not just the main file —
`install.sh` step 7 sets `u:picket:r` on `knock_knock.db*` and a **default**
ACL on the directory so the sidecar files knock-knock creates later inherit
it. If `knock_knock.db` did not exist yet when the script ran, re-apply
`setfacl -m u:picket:r /opt/knock-knock/data/knock_knock.db*` before the
first run. (A read-only connection on SQLite ≥ 3.22 copes with a read-only
`-shm` by keeping the WAL index in heap memory; a torn read across a
concurrent commit is retried on the next timer tick, never published.)

**Box smoke — two `--no-push` runs, nothing leaves the box.** First with the
GeoIP database deliberately pointed at a missing file: this proves the C2
behaviour (a missing MaxMind DB omits `country`, it does not crash) and, on a
box without `/etc/GeoIP.conf`, is simply the normal run:

```bash
sudo -Hu picket /opt/socdesk/.venv/bin/python -m tools.picket.exporter \
  --db /opt/knock-knock/data/knock_knock.db --state /var/lib/picket/state.json \
  --out /srv/picket-export/export.json --repo-dir /srv/picket-export \
  --sensor-id picket-1 --knockknock-dir /opt/knock-knock \
  --geoip-db /nonexistent.mmdb --no-push; echo "exit $?"
grep -c '"country"' /srv/picket-export/export.json || true
```

Expected: `exit 0`, one stderr line `geoip: ... — publishing without
country`, and the `grep` count is `0` (no row carries `country`). Then the
real `--no-push` run (writes `export.json` locally, never touches the export
repo — inspect it before anything goes out):

```bash
sudo -Hu picket /opt/socdesk/.venv/bin/python -m tools.picket.exporter \
  --db /opt/knock-knock/data/knock_knock.db --state /var/lib/picket/state.json \
  --out /srv/picket-export/export.json --repo-dir /srv/picket-export \
  --sensor-id picket-1 --knockknock-dir /opt/knock-knock \
  --geoip-db /usr/share/GeoIP/GeoLite2-Country.mmdb --no-push
cat /srv/picket-export/export.json
```

Note the exporter first asks `https://ifconfig.me` for the box's public IPv4
(to drop the box's own rows and to publish `sensor.public_ip_sha256`); if that
lookup yields nothing usable it prints `REFUSED (public-ip): ...` and exits
`4` without touching `state.json` — outbound HTTPS must work.

Then a real run (pushes):

```bash
sudo -Hu picket /opt/socdesk/.venv/bin/python -m tools.picket.exporter \
  --db /opt/knock-knock/data/knock_knock.db --state /var/lib/picket/state.json \
  --out /srv/picket-export/export.json --repo-dir /srv/picket-export \
  --sensor-id picket-1 --knockknock-dir /opt/knock-knock \
  --geoip-db /usr/share/GeoIP/GeoLite2-Country.mmdb
```

`install.sh` already enabled the timer (`picket-export.timer`, running at
`:05`/`:35`, six minutes before the pipeline's cron). Watch it in production:

```bash
journalctl -u picket-export -f
journalctl -u picket-export --since "-1h"
```

A `REFUSED (schema): ...` (exit 2), `REFUSED (size): ...` (exit 3) or
`REFUSED (public-ip): ...` (exit 4) line means the exporter declined to
publish rather than push something invalid — check the message, fix the
underlying cause, and let the next timer tick retry. A `geoip: ...` line is
not a refusal: the export went out without per-IP `country` (§4). A
`state: ... unreadable ... starting a fresh ring` line means `state.json` was
corrupt (e.g. power loss) and the 7-day ring restarted from empty — `hits_7d`
figures read low for up to 7 days, as after a rebuild (§7).

**Dogfood note — SMTP.** Hetzner and Oracle Cloud block inbound 25/tcp by
default on new accounts/instances; expect the SMTP protocol to show zero
knocks until the provider unblocks the port. That is the provider, not the
sensor.

## 6. Confirm the protocol map

The exporter refuses to guess protocol IDs — `load_proto_names()` reads
knock-knock's own `protocols/registry.py` at runtime and raises if the shape
doesn't match what `assemble_export()` expects. Confirm the map on the pinned
tag before you rely on it, and keep a copy of the output:

```bash
cd /opt/knock-knock
python3 -c "from protocols.registry import DEFINITIONS; print({d.name: d.proto_id for d in DEFINITIONS})"
```

**Build-time check — auth-attempt vs. bare-connect logging.** Per spec §3.9,
confirm for each protocol module in `/opt/knock-knock` whether a "knock" is
recorded on a bare TCP connect or only after a credential/auth attempt (this
changes how `hits_total`/`hits_7d` should be read — a bare-connect protocol
will show much higher counts than an auth-gated one for the same attacker
interest):

```bash
grep -RniE 'record_knock|log_knock|on_connect|on_auth' /opt/knock-knock/protocols/*.py
```

Record both the protocol-ID map and the per-module auth-attempt-vs-bare-connect
answer in [docs/PICKET.md](../../docs/PICKET.md) (§3/§8) so future exporter
runs and readers of the export don't have to re-derive it.

## 7. Rebuild from scratch

If the box needs to be destroyed and replaced (suspected compromise, provider
migration, or just periodic hygiene):

1. Destroy the VPS instance at the provider.
2. Provision a fresh one (§2) and re-run `install.sh` (§3–§5) end to end.
3. Rotate the deploy key (§8) — a rebuilt box gets a **new** SSH keypair; the
   old public key must be removed from the export repo's deploy keys.

`state.json` (the 7-day delta ring, `/var/lib/picket/state.json`) does **not**
carry over — a fresh box starts with `new_state()`. The 7-day ring re-fills
gradually: `hits_7d` figures will read low/zero for up to 7 days after a
rebuild, and this is expected, not a bug. The exported `sensor.ring_reset_at`
field will not be set (that only fires when a counter goes backwards, not on
a fresh start) — note the rebuild date separately if it matters for your own
records.

## 8. Incident response

Signs the box itself (not just the honeypot service) may be compromised:
unexpected outbound connections beyond the export repo push, processes you
didn't start, modified `install.sh`/`exporter.py` on disk, unexpected changes
to `/etc/ssh/sshd_config.d/00-picket.conf` (or `sshd -T` no longer showing
the §3 lines) or `ufw` rules, or a `picket-export` timer run that pushed
something you didn't expect.

If you see any of these:

1. **Destroy the box immediately** — do not try to clean it in place. Bait
   boxes are disposable by design.
2. **Rotate the deploy key** on `socdesk-picket-export` — remove the
   compromised box's public key from Settings → Deploy keys before
   provisioning a replacement (§7). A leaked private key without a rotated
   deploy key would let the attacker keep pushing to the export repo after
   the box is gone.
3. **Inspect the export repo's git history** for vandalized commits (`git log
   --oneline`, diff any commit authored outside the timer's normal :05/:35
   cadence or with unexpected content).
4. The pipeline's schema gate and last-known-good fallback mean **the site
   was protected regardless** — a malformed or malicious `export.json` is
   rejected at validation and the site keeps serving the last good snapshot.
   Incident response here is about the sensor box and the export repo, not
   about socdesk.io having been at risk.

## 9. Attribution obligations

- **MaxMind GeoLite2** — this product includes GeoLite2 data created by
  MaxMind, available from
  [https://www.maxmind.com](https://www.maxmind.com). Required by MaxMind's
  GeoLite2 End User License Agreement wherever the GeoLite2 database is used.
- **knock-knock** — MIT License, © the knock-knock project contributors
  ([github.com/djkurlander/knock-knock](https://github.com/djkurlander/knock-knock)).
  The MIT license text must be preserved wherever the software is
  redistributed; SOCDesk runs it unmodified via the pinned `KK_TAG`.
