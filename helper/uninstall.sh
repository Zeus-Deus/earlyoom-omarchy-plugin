#!/usr/bin/env bash
# Removes OOM Guard's earlyoom link. earlyoom goes back to /etc/default/earlyoom alone.
# Your protected list (~/.config/oomguard) is kept.
set -euo pipefail
if [[ $EUID != 0 ]]; then
  printf '%s\n' 'Run it with sudo: sudo bash helper/uninstall.sh'
  exit 1
fi
systemctl disable --now oomguard-earlyoom-sync.path 2>/dev/null || true
rm -f /etc/systemd/system/oomguard-earlyoom-sync.path \
      /etc/systemd/system/oomguard-earlyoom-sync.service \
      /etc/systemd/system/earlyoom.service.d/50-oomguard.conf \
      /etc/oomguard/earlyoom.env \
      /usr/lib/oomguard/rules.py \
      /usr/lib/oomguard/oomguard-earlyoom-sync
rmdir /usr/lib/oomguard /etc/oomguard /etc/systemd/system/earlyoom.service.d 2>/dev/null || true
systemctl daemon-reload
systemctl try-restart earlyoom.service
printf '%s\n' 'OOM Guard earlyoom link removed.'
