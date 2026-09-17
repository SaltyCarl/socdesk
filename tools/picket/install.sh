#!/usr/bin/env bash
# SOCDesk PICKET box bootstrap. Idempotent. Run as root on a FRESH Debian/Ubuntu VPS.
# READ tools/picket/README.md FIRST. Step 1 changes your SSH port: keep this session open,
# test the new port from a second terminal before you disconnect.
set -euo pipefail
ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-2222}"
ADMIN_ALLOW_CIDR="${ADMIN_ALLOW_CIDR:?set ADMIN_ALLOW_CIDR to your admin source, e.g. 203.0.113.9/32}"
KK_TAG="${KK_TAG:?set KK_TAG to the pinned knock-knock release tag}"
EXPORT_REPO="${EXPORT_REPO:-git@github.com:SaltyCarl/socdesk-picket-export.git}"

# 1. move real sshd off :22 (knock-knock needs it), key-only
sed -i "s/^#\?Port .*/Port ${ADMIN_SSH_PORT}/; s/^#\?PasswordAuthentication .*/PasswordAuthentication no/" /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd
echo ">> sshd now on ${ADMIN_SSH_PORT}. TEST IT FROM ANOTHER TERMINAL BEFORE CONTINUING."; read -r -p "Press enter when verified"

# 2. firewall: admin SSH from allow-list only; honeypot ports open to all; nothing else
apt-get update -q && apt-get install -y -q ufw git python3-venv curl docker.io docker-compose-plugin geoipupdate
ufw --force reset
ufw default deny incoming; ufw default allow outgoing
ufw allow from "${ADMIN_ALLOW_CIDR}" to any port "${ADMIN_SSH_PORT}" proto tcp
for p in 21 22 23 25 80 445 3389; do ufw allow "${p}/tcp"; done
ufw allow 5060/udp; ufw allow 5060/tcp
ufw --force enable

# 3. knock-knock, pinned, host networking, rollups only, dashboard on localhost
mkdir -p /opt && cd /opt
[ -d knock-knock ] || git clone --branch "${KK_TAG}" --depth 1 https://github.com/djkurlander/knock-knock.git
cd /opt/knock-knock
[ -f .env ] || cp .env.example .env
grep -q '^WEB_HOST=' .env || echo 'WEB_HOST=127.0.0.1' >> .env      # verify the var name on the pinned tag (README)
grep -q '^SOURCE_ID=' .env || echo 'SOURCE_ID=picket-1' >> .env
sed -i 's/^SAVE_KNOCKS=.*/# SAVE_KNOCKS off: rollups only/' .env
docker compose up -d

# 4. exporter: this repo's tools/picket, its own venv, its own requirements
id -u picket &>/dev/null || useradd -r -m -d /var/lib/picket -s /usr/sbin/nologin picket
mkdir -p /opt/socdesk /srv/picket-export /var/lib/picket
# copy tools/picket + collectors/base.py + schemas/picket_export.schema.json here (see README §3)
python3 -m venv /opt/socdesk/.venv && /opt/socdesk/.venv/bin/pip install -q -r /opt/socdesk/tools/picket/requirements.txt
[ -d /srv/picket-export/.git ] || sudo -u picket git clone "${EXPORT_REPO}" /srv/picket-export
chown -R picket:picket /srv/picket-export /var/lib/picket
install -m 644 /opt/socdesk/tools/picket/systemd/picket-export.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now picket-export.timer
systemctl list-timers picket-export.timer --no-pager
