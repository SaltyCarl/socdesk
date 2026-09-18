#!/usr/bin/env bash
# SOCDesk PICKET box bootstrap. Idempotent. Run as root, INTERACTIVELY (it pauses for
# you), on a FRESH Debian 12 / Ubuntu 24.04 VPS. READ tools/picket/README.md FIRST.
# Step 2 moves your SSH port: keep this session open and test the new port from a
# second terminal before you press enter. Stage /opt/socdesk (README §5 copy block)
# BEFORE running this — step 6 checks for it and stops if it is missing.
#
# Environment variables this script reads:
#   ADMIN_ALLOW_CIDR     REQUIRED  your admin source IP/CIDR, e.g. 203.0.113.9/32
#   KK_TAG               REQUIRED  pinned knock-knock release tag, e.g. v3.0.0
#   ADMIN_SSH_PORT       optional  real sshd port after hardening         (default 2222)
#   ADMIN_USER           optional  the ONE account sshd admits (AllowUsers) (default root)
#   EXPORT_REPO          optional  SSH push URL of the export repo (deploy key)
#   EXPORT_REPO_HTTPS    optional  HTTPS read-only clone URL of the same repo
#   MAXMIND_ACCOUNT_ID   optional  both set -> knock-knock .env + /etc/GeoIP.conf are
#   MAXMIND_LICENSE_KEY  optional  written and GeoLite2-Country fetched; unset -> the
#                                  export omits per-IP `country` until configured (§4)
set -euo pipefail
ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-2222}"
ADMIN_USER="${ADMIN_USER:-root}"
ADMIN_ALLOW_CIDR="${ADMIN_ALLOW_CIDR:?set ADMIN_ALLOW_CIDR to your admin source, e.g. 203.0.113.9/32}"
KK_TAG="${KK_TAG:?set KK_TAG to the pinned knock-knock release tag}"
EXPORT_REPO="${EXPORT_REPO:-git@github.com:SaltyCarl/socdesk-picket-export.git}"
EXPORT_REPO_HTTPS="${EXPORT_REPO_HTTPS:-https://github.com/SaltyCarl/socdesk-picket-export.git}"

# 1. packages FIRST — a package failure must never strand a half-hardened box.
. /etc/os-release                       # ID=debian|ubuntu, VERSION_CODENAME=bookworm|noble
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q sudo ufw git curl python3-venv acl unattended-upgrades ca-certificates gnupg
apt-get install -y -q geoipupdate || echo ">> geoipupdate package unavailable — configure GeoIP by hand (README §4); the export omits country until then"
# Docker Engine + the compose plugin from Docker's own apt repo, one path for both
# targets (the distro packages differ: Debian 12 ships docker-compose v1, Ubuntu
# 24.04 docker-compose-v2 — neither is the `docker compose` the runbook uses).
if ! docker compose version >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
systemctl enable --now docker
systemctl enable --now unattended-upgrades

# 2. real sshd off :22 (knock-knock needs it), key-only, ONE admin account — as a
#    drop-in. sshd keeps the FIRST value it reads for each keyword and the Include of
#    sshd_config.d/*.conf comes first, so 00-picket.conf wins over sshd_config AND
#    over a provider cloud-init drop-in (50-cloud-init.conf: PasswordAuthentication yes).
install -d -m 755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-picket.conf <<EOF
Port ${ADMIN_SSH_PORT}
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
AllowUsers ${ADMIN_USER}
EOF
sshd -t                                 # syntax-check before touching the running daemon
if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
  # Ubuntu 24.04: sshd is socket-activated and `Port` in sshd_config is IGNORED —
  # hand the listener back to sshd itself. Your current session survives this.
  # Ubuntu's documented revert: the 00-socket.conf drop-in ties ssh.service back to
  # ssh.socket, so it must go (with the socket's address override) before the service
  # is enabled on its own — otherwise sshd inherits the :22 listener and ignores Port.
  systemctl disable --now ssh.socket
  rm -f /etc/systemd/system/ssh.service.d/00-socket.conf /etc/systemd/system/ssh.socket.d/addresses.conf
  systemctl daemon-reload
  systemctl enable --now ssh.service
  systemctl restart ssh.service
else
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
fi
echo ">> CONFIGURED sshd values (sshd -T reads the config, not the sockets):"
sshd -T | grep -Ei '^(port|passwordauthentication|kbdinteractiveauthentication|permitrootlogin|allowusers) ' || true
echo ">> LISTENING sshd ports (this is what is actually enforced — expect :${ADMIN_SSH_PORT}, not :22):"
ss -ltnp | grep -E 'sshd' || true
systemctl is-active ssh.socket >/dev/null 2>&1 && echo ">> WARNING: ssh.socket is still active — sshd is still on :22; re-run this step" || true
echo ">> sshd now on ${ADMIN_SSH_PORT}, key-only, admitting only '${ADMIN_USER}'."
echo ">> TEST IT FROM ANOTHER TERMINAL BEFORE CONTINUING:  ssh -p ${ADMIN_SSH_PORT} ${ADMIN_USER}@<ip>"
read -r -p "Press enter when verified"

# 3. firewall: admin SSH from the allow-list only; honeypot ports open to all; nothing else
ufw --force reset
ufw default deny incoming; ufw default allow outgoing
ufw allow from "${ADMIN_ALLOW_CIDR}" to any port "${ADMIN_SSH_PORT}" proto tcp
for p in 21 22 23 25 80 445 3389; do ufw allow "${p}/tcp"; done
ufw allow 5060/udp; ufw allow 5060/tcp
ufw --force enable

# 4. knock-knock, pinned, HOST networking, rollups only, dashboard bound to localhost
mkdir -p /opt && cd /opt
[ -d knock-knock ] || git clone --branch "${KK_TAG}" --depth 1 https://github.com/djkurlander/knock-knock.git
cd /opt/knock-knock
[ -f .env ] || cp .env.example .env
# Host networking is what puts the dashboard port under ufw. Under the bridge
# docker-compose.yml Docker publishes 8080 through its own iptables chain, which
# BYPASSES ufw — so this line is a control, not a preference.
grep -q '^COMPOSE_FILE=docker-compose.host.yml' .env || echo 'COMPOSE_FILE=docker-compose.host.yml' >> .env
grep -q '^WEB_LISTEN=' .env || echo 'WEB_LISTEN=127.0.0.1' >> .env   # docker-compose.host.yml: uvicorn --host ${WEB_LISTEN:-0.0.0.0}
grep -q '^SOURCE_ID=' .env || echo 'SOURCE_ID=picket-1' >> .env
grep -q '^ENABLED_PROTOCOLS=' .env || echo 'ENABLED_PROTOCOLS=SSH,TNET,FTP,RDP,SMB,SIP,HTTP,SMTP' >> .env   # spec §3.1 core eight; TNET is knock-knock's id for Telnet
sed -i 's/^SAVE_KNOCKS=.*/# SAVE_KNOCKS off: rollups only/' .env
if [ -n "${MAXMIND_ACCOUNT_ID:-}" ] && [ -n "${MAXMIND_LICENSE_KEY:-}" ]; then
  # knock-knock's own geoipupdate container (City/ASN -> lat/lng, into a Docker volume)
  sed -i '/^MAXMIND_ACCOUNT_ID=/d; /^MAXMIND_LICENSE_KEY=/d' .env
  printf 'MAXMIND_ACCOUNT_ID=%s\nMAXMIND_LICENSE_KEY=%s\n' "${MAXMIND_ACCOUNT_ID}" "${MAXMIND_LICENSE_KEY}" >> .env
fi
# --build makes the pin explicit: the compose file names both `image: …:latest` and
# `build: .`, and only a local build is guaranteed to be the checked-out KK_TAG.
docker compose up -d --build

# 5. HOST GeoLite2-Country for the exporter's per-IP `country`. knock-knock's container
#    fetches GeoLite2-ASN + GeoLite2-City into a named Docker volume — not the host,
#    not the Country edition — so the exporter needs its own copy.
if [ -n "${MAXMIND_ACCOUNT_ID:-}" ] && [ -n "${MAXMIND_LICENSE_KEY:-}" ]; then
  install -d -m 755 /usr/share/GeoIP
  cat > /etc/GeoIP.conf <<EOF
AccountID ${MAXMIND_ACCOUNT_ID}
LicenseKey ${MAXMIND_LICENSE_KEY}
EditionIDs GeoLite2-Country
DatabaseDirectory /usr/share/GeoIP
EOF
  chmod 600 /etc/GeoIP.conf
  geoipupdate || echo ">> geoipupdate failed — the export omits country until /etc/GeoIP.conf works (README §4)"
  if systemctl cat geoipupdate.timer >/dev/null 2>&1; then systemctl enable --now geoipupdate.timer; fi
else
  echo ">> MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY unset: the export will OMIT per-IP country"
  echo ">> until /etc/GeoIP.conf is configured (README §4). Everything else publishes."
fi

# 6. exporter: this repo's tools/picket (staged BEFORE this script, README §5), own venv
id -u picket &>/dev/null || useradd -r -m -d /var/lib/picket -s /usr/sbin/nologin picket
install -d -o picket -g picket -m 750 /var/lib/picket /srv/picket-export
mkdir -p /opt/socdesk
[ -f /opt/socdesk/tools/picket/requirements.txt ] || { echo "!! /opt/socdesk/tools/picket is not staged — run README §5's copy block first, then re-run this script"; exit 1; }
mkdir -p /opt/socdesk/collectors && [ -f /opt/socdesk/collectors/__init__.py ] || touch /opt/socdesk/collectors/__init__.py
python3 -m venv /opt/socdesk/.venv && /opt/socdesk/.venv/bin/pip install -q -r /opt/socdesk/tools/picket/requirements.txt

# 7. let the unprivileged exporter READ knock-knock's SQLite. monitor.py uses WAL, so
#    the -wal and -shm files must be readable too; the default ACL covers files
#    knock-knock creates later.
setfacl -m u:picket:rx /opt/knock-knock /opt/knock-knock/data
setfacl -d -m u:picket:r /opt/knock-knock/data
setfacl -m u:picket:r /opt/knock-knock/data/knock_knock.db* 2>/dev/null \
  || echo ">> knock_knock.db not created yet — once knock-knock has started run: setfacl -m u:picket:r /opt/knock-knock/data/knock_knock.db*"

# 8. deploy key for the export repo — generated HERE, as picket, so the first push
#    has a key to use; you register the public key printed at the end.
install -d -o picket -g picket -m 700 /var/lib/picket/.ssh
[ -f /var/lib/picket/.ssh/id_ed25519 ] || sudo -Hu picket ssh-keygen -q -t ed25519 -N '' -f /var/lib/picket/.ssh/id_ed25519 -C picket-export
grep -qs 'github.com' /var/lib/picket/.ssh/known_hosts || sudo -Hu picket sh -c 'ssh-keyscan -t ed25519 github.com >> /var/lib/picket/.ssh/known_hosts'
sudo -Hu picket git config --global user.name picket
sudo -Hu picket git config --global user.email picket@socdesk.io

# 9. export repo: keyless read-only HTTPS clone (the repo is public), pushes over SSH
#    with the deploy key. GIT_TERMINAL_PROMPT=0 fails fast instead of asking for a password.
#    (`env` carries the variable past sudo's env_reset; a bare VAR=x prefix would be stripped.)
[ -d /srv/picket-export/.git ] || sudo -Hu picket env GIT_TERMINAL_PROMPT=0 git clone -q "${EXPORT_REPO_HTTPS}" /srv/picket-export
sudo -Hu picket git -C /srv/picket-export remote set-url --push origin "${EXPORT_REPO}"
chown -R picket:picket /srv/picket-export /var/lib/picket

# 10. unit + timer LAST
install -m 644 /opt/socdesk/tools/picket/systemd/picket-export.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now picket-export.timer
systemctl list-timers picket-export.timer --no-pager
cat <<EOF

>> REGISTER THIS DEPLOY KEY on github.com/SaltyCarl/socdesk-picket-export:
>>   Settings -> Deploy keys -> Add deploy key -> paste -> tick "Allow write access".
>>   Write-scoped, on the export repo ONLY — never a key with broader scope.

$(cat /var/lib/picket/.ssh/id_ed25519.pub)

>> Until it is registered every timer run ends in a git push error from the exporter
>> (journalctl -u picket-export) — that error is the signal, not a fault. The first
>> successful push confirms the key. Before relying on the timer, run README §5's
>> --no-push smoke checks by hand.
EOF
