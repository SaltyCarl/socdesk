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

`install.sh` is idempotent but **step 1 changes your SSH port and disables
password auth — if you get this wrong and disconnect, you are locked out**
(cloud console / rescue mode is your only way back in). Do not skip the
verification pause.

**Before running `install.sh`:** stage the exporter files on the box — the
script's own step 4 runs
`pip install -q -r /opt/socdesk/tools/picket/requirements.txt`, which requires
those files to already be present at `/opt/socdesk/tools/picket/`. Run §5
"Exporter"'s copy block now, from your workstation, **using port 22** (at this
point in the process the real sshd hasn't moved yet — that only happens a few
lines below, once you run `install.sh` itself). Come back here once the copy
is done and verified.

Set the required environment variables and run the script as root on the
fresh box:

```bash
export ADMIN_SSH_PORT=2222                    # optional, defaults to 2222
export ADMIN_ALLOW_CIDR=203.0.113.9/32        # REQUIRED: your admin source IP/CIDR
export KK_TAG=v3.0.0                          # REQUIRED: pinned knock-knock release tag — list them first: git ls-remote --tags https://github.com/djkurlander/knock-knock.git
export EXPORT_REPO=git@github.com:SaltyCarl/socdesk-picket-export.git   # optional, this is the default
bash tools/picket/install.sh
```

Step 1 of the script moves real sshd to `ADMIN_SSH_PORT`, disables password
auth, restarts sshd, then **stops and prints a prompt**. Before pressing
enter:

```bash
# from a SECOND terminal, do not close the first
ssh -p 2222 root@<ip>
```

Only press enter in the first terminal once that second connection succeeds.
If it fails, fix `/etc/ssh/sshd_config` from the still-open first session —
do not disconnect it.

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

MaxMind values in `/opt/knock-knock/.env` (GeoLite2 free tier — see
[Attribution obligations](#9-attribution-obligations)):

```
MAXMIND_ACCOUNT_ID=<your account id>
MAXMIND_LICENSE_KEY=<your license key>
```

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

Confirm the dashboard is **not** reachable from outside — it must only be
bound to localhost:

```bash
curl -m 3 http://<ip>:8080          # from an EXTERNAL machine — must fail/timeout
```

To view it yourself, tunnel over SSH instead:

```bash
ssh -p 2222 -L 8080:127.0.0.1:8080 root@<ip>
# then open http://127.0.0.1:8080 locally
```

**Build-time check — confirm the bind variable name on the pinned tag.**
knock-knock `v3.0.0`'s `.env.example` defines no host/bind variable at all, so
the `WEB_HOST=127.0.0.1` line `install.sh` writes is a no-op on that tag; the
firewall rules in §3 (no rule for 8080) are the control that keeps the
dashboard private, and the external `curl` check below is how you prove it.
`install.sh` writes `WEB_HOST=127.0.0.1` into `.env` as a guess; knock-knock's
actual variable name can differ by release. Verify it explicitly before
trusting that the dashboard is bound to localhost:

```bash
cd /opt/knock-knock
grep -RniE 'host|bind|0\.0\.0\.0' .env.example docker-compose.yml
```

If the pinned tag uses a different variable name (e.g. `DASHBOARD_HOST`,
`FLASK_RUN_HOST`) than `WEB_HOST`, edit `/opt/knock-knock/.env` to use the
correct name, `docker compose up -d` again, and re-run the `curl` check
above until it fails as expected.

## 5. Exporter

If you haven't already (§3 tells you to do this *before* running
`install.sh`, since its step 4 pip-installs from these files), copy the
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

`collectors/base.py` imports as `collectors.base`, so also create an empty
package marker next to it (no `collectors/__init__.py` stub is copied from
this repo — create it fresh on the box):

```bash
mkdir -p /opt/socdesk/collectors
touch /opt/socdesk/collectors/__init__.py
```

Generate the exporter's own deploy key (as the unprivileged `picket` user
`install.sh` created) and register it, **write-enabled**, on the export repo:

```bash
sudo -u picket ssh-keygen -t ed25519 -C picket -f /var/lib/picket/.ssh/id_ed25519 -N ""
cat /var/lib/picket/.ssh/id_ed25519.pub
```

Add that public key at `github.com/SaltyCarl/socdesk-picket-export` →
**Settings → Deploy keys → Add deploy key** → paste it → check **Allow write
access**.

Trust GitHub's host key for the `picket` user before the first push (`git
clone`/`git push` will otherwise hang on the unknown-host prompt):

```bash
sudo -u picket ssh-keyscan -t ed25519 github.com >> /var/lib/picket/.ssh/known_hosts
sudo -u picket git config --global user.email "picket@socdesk.io"
sudo -u picket git config --global user.name "SOCDesk PICKET exporter"
```

First run by hand with `--no-push` (writes `export.json` locally, never
touches the export repo — inspect it before anything goes out):

```bash
sudo -u picket /opt/socdesk/.venv/bin/python -m tools.picket.exporter \
  --db /opt/knock-knock/data/knocks.db --state /var/lib/picket/state.json \
  --out /srv/picket-export/export.json --repo-dir /srv/picket-export \
  --sensor-id picket-1 --knockknock-dir /opt/knock-knock \
  --geoip-db /usr/share/GeoIP/GeoLite2-Country.mmdb --no-push
cat /srv/picket-export/export.json
```

Then a real run (pushes):

```bash
sudo -u picket /opt/socdesk/.venv/bin/python -m tools.picket.exporter \
  --db /opt/knock-knock/data/knocks.db --state /var/lib/picket/state.json \
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

A `REFUSED (schema): ...` or `REFUSED (size): ...` line means the exporter
declined to publish rather than push something invalid — check the message,
fix the underlying data, and let the next timer tick retry.

## 6. Confirm the protocol map

The exporter refuses to guess protocol IDs — `load_proto_names()` reads
knock-knock's own `protocols/registry.py` at runtime and raises if the shape
doesn't match what `assemble_export()` expects. Confirm the map on the pinned
tag before you rely on it, and keep a copy of the output:

```bash
cd /opt/knock-knock
python3 -c "from protocols.registry import PROTOCOL_META; print({n: m['definition'].proto_id for n,m in PROTOCOL_META.items()})"
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
to `/etc/ssh/sshd_config` or `ufw` rules, or a `picket-export` timer run that
pushed something you didn't expect.

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
