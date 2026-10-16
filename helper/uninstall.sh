#!/usr/bin/env bash
# Removes OOM Guard's earlyoom link. earlyoom goes back to /etc/default/earlyoom
# alone. Only files that start with the OOM Guard marker are removed; anything
# else at those paths is left in place and reported. Your protected list
# (~/.config/oomguard) is kept.
set -euo pipefail
if [[ $EUID != 0 ]]; then
  printf '%s\n' 'Run it with sudo: sudo bash helper/uninstall.sh'
  exit 1
fi
marker='# Managed by OOM Guard (io.github.zeus-deus.oomguard).'
# Files OOM Guard 0.1.x wrote before it had a marker line, by exact SHA-256.
legacy_hashes=(
  2d3d0836c20f38b5bad306c2a111fbfe94a65c4edd51e88b4ec899724f0f547e 85b79bd24156f1b852e7c450229cb9c3a17d3645d640c067059c609307c36fa4
  fbf69bc593b02c81bc34b49d43444beaef12b4ea16f09eca912b74cae198c81d 1c7af966a65d318e715fd85469dc8c58fb9abbd091068f8eeca242629c4c25c2
  85464221c1aab858e66ece552579f37491f4dcad263076da822f0820e537027c 10bd32f4d68b8a9d935dec26a5c5ceeaf277a4d61c0837cff81369bca7f88c8d
)
legacy_dropin_hash=10bd32f4d68b8a9d935dec26a5c5ceeaf277a4d61c0837cff81369bca7f88c8d
# Written by OOM Guard: the marker in its first two lines, or a 0.1.x file by
# exact hash. Nothing else is assumed to be ours.
ours() {
  local f=$1 h
  [[ -f $f && ! -L $f ]] || return 1
  [[ $(sed -n '1,2p' "$f") == *"$marker"* ]] && return 0
  h=$(sha256sum < "$f" | cut -d' ' -f1)
  for k in "${legacy_hashes[@]}"; do [[ $h == "$k" ]] && return 0; done
  return 1
}
# OOM Guard 0.1.x also generated two files without the marker: the path unit
# and the env file. Their contents varied, so they cannot be recognised by
# hash. They are only offered for replacement, shown in full, and touched
# only after the user answers yes in this terminal.
legacy_candidate() {
  local f=$1 d=/etc/systemd/system/earlyoom.service.d/50-oomguard.conf
  [[ -f $f && ! -L $f && -f $d && ! -L $d && $(sha256sum < "$d" | cut -d' ' -f1) == "$legacy_dropin_hash" ]] || return 1
  [[ $f == /etc/systemd/system/oomguard-earlyoom-sync.path || $f == /etc/oomguard/earlyoom.env ]]
}
confirm_legacy() {
  local verb=$1; shift
  (( $# )) || return 0
  [[ -t 0 ]] || return 1
  printf '\nThese files have no OOM Guard ownership line. OOM Guard 0.1 created files\n'
  printf 'at these paths, but they may have been changed since:\n'
  for f in "$@"; do printf '\n--- %s\n' "$f"; head -c 4096 "$f"; done
  printf '\n'
  local answer
  read -r -p "$verb them? [y/N] " answer
  [[ $answer == [yY] || $answer == [yY][eE][sS] ]]
}
# Decide ownership of everything first: the 0.1.x files are recognised by the
# 0.1.x drop-in, which is itself among the files removed below.
declare -A mine=()
legacy=()
for f in /etc/systemd/system/oomguard-earlyoom-sync.timer \
         /etc/systemd/system/oomguard-earlyoom-sync.path \
         /etc/systemd/system/oomguard-earlyoom-sync.service \
         /etc/systemd/system/earlyoom.service.d/50-oomguard.conf \
         /etc/oomguard/earlyoom.env \
         /usr/lib/oomguard/rules.py \
         /usr/lib/oomguard/oomguard-earlyoom-sync; do
  if [[ -L $f ]]; then printf 'Left alone (symlink): %s\n' "$f"
  elif [[ -e $f ]]; then
    if ours "$f"; then mine[$f]=1
    elif legacy_candidate "$f"; then legacy+=("$f")
    else printf 'Left alone (not written by OOM Guard): %s\n' "$f"; fi
  fi
done
if confirm_legacy Remove "${legacy[@]}"; then
  for f in "${legacy[@]}"; do mine[$f]=1; done
else
  for f in "${legacy[@]}"; do printf 'Left alone: %s\n' "$f"; done
fi
# Units are stopped only when their file is ours.
[[ -n ${mine[/etc/systemd/system/oomguard-earlyoom-sync.timer]:-} ]] && { systemctl disable --now oomguard-earlyoom-sync.timer 2>/dev/null || true; }
[[ -n ${mine[/etc/systemd/system/oomguard-earlyoom-sync.path]:-} ]] && { systemctl disable --now oomguard-earlyoom-sync.path 2>/dev/null || true; }
for f in "${!mine[@]}"; do rm -f -- "$f"; done
# Bytecode that 0.1.x left for its own rules.py (the sync now runs with -B).
rm -f /usr/lib/oomguard/__pycache__/rules.cpython-*.pyc
rmdir /usr/lib/oomguard/__pycache__ 2>/dev/null || true
rmdir /usr/lib/oomguard /etc/oomguard /etc/systemd/system/earlyoom.service.d 2>/dev/null || true
systemctl daemon-reload
# earlyoom's unit allows 5 starts in 10 s. Keep at least 10 s since the last
# restart OOM Guard caused (the stamp in /run is shared with the sync and kept
# here on purpose), so a quick link/unlink never leaves earlyoom stopped.
stamp=/run/oomguard/last-restart
if [[ -f $stamp ]]; then
  wait=$(( $(stat -c %Y "$stamp") + 10 - $(date +%s) ))
  (( wait > 0 && wait <= 10 )) && sleep "$wait"
fi
install -d -m 0755 /run/oomguard
date +%s > "$stamp"
systemctl try-restart earlyoom.service
printf '%s\n' 'OOM Guard earlyoom link removed.'
