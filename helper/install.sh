#!/usr/bin/env bash
# OOM Guard: optional earlyoom link. Only needed if you run earlyoom.
# Protecting apps from systemd-oomd (Omarchy's default) needs none of this.
#
# Installs, all owned by root and all starting with the OOM Guard marker line:
#   /usr/lib/oomguard/{rules.py,oomguard-earlyoom-sync}
#   /etc/systemd/system/oomguard-earlyoom-sync.{service,timer}
#   /etc/systemd/system/earlyoom.service.d/50-oomguard.conf
# Every 15 s the timer reads each human user's ~/.config/oomguard/protected.json
# and gives earlyoom "--ignore <their protected names>". Everything else in
# /etc/default/earlyoom stays as it is. A file at any of these paths that does
# not carry the marker is never replaced: the script stops before changing
# anything.
set -euo pipefail
if [[ $EUID != 0 ]]; then
  printf '%s\n' 'Run it with sudo: sudo bash helper/install.sh'
  exit 1
fi
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
marker='# Managed by OOM Guard (io.github.zeus-deus.oomguard).'
fail() { printf '%s\n' "$1" 'Nothing was changed.'; exit 1; }
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

systemctl daemon-reload
[[ $(systemctl show -p LoadState --value earlyoom.service) == loaded ]] ||
  fail 'earlyoom is not installed. Omarchy uses systemd-oomd, which OOM Guard handles without this step.'

# Only the unit shape we know: the packaged ExecStart, untouched by other
# drop-ins. Anything else could lose options the administrator set.
ours_dropin=/etc/systemd/system/earlyoom.service.d/50-oomguard.conf
fragment=$(systemctl show -p FragmentPath --value earlyoom.service)
[[ $fragment == /usr/lib/systemd/system/earlyoom.service ]] ||
  fail "earlyoom.service comes from $fragment, not the packaged unit; refusing to override it."
# Any ExecStart key, with any indentation (systemd strips it), in the fragment
# or in any drop-in but ours. Unreadable files fail closed.
execstart_lines() { grep -E '^[[:space:]]*ExecStart[[:space:]]*=' "$1"; }
[[ -r $fragment ]] || fail "Cannot read $fragment."
[[ $(execstart_lines "$fragment" | wc -l) == 1 && $(execstart_lines "$fragment" | sed -E 's/^[[:space:]]+//; s/[[:space:]]*=[[:space:]]*/=/; s/[[:space:]]+$//') == 'ExecStart=/usr/bin/earlyoom $EARLYOOM_ARGS' ]] ||
  fail 'earlyoom.service does not start "/usr/bin/earlyoom $EARLYOOM_ARGS"; refusing to guess its command line.'
dropins=$(systemctl show -p DropInPaths --value earlyoom.service) || fail 'Cannot list earlyoom drop-ins.'
for d in $dropins; do
  [[ $d == "$ours_dropin" ]] && continue
  [[ -r $d ]] || fail "Cannot read $d."
  ! execstart_lines "$d" >/dev/null || fail "$d already changes earlyoom's ExecStart; refusing to override it."
done
# And what systemd actually parsed, the same command (plus ours if present).
want='argv[]=/usr/bin/earlyoom $EARLYOOM_ARGS ;'
[[ -e $ours_dropin ]] && want='argv[]=/usr/bin/earlyoom $EARLYOOM_ARGS $OOMGUARD_ARGS ;'
effective=$(systemctl show -p ExecStart --value earlyoom.service) || fail 'Cannot read earlyoom ExecStart.'
[[ $(grep -o 'argv\[\]=' <<<"$effective" | wc -l) == 1 && $effective == *"$want"* ]] ||
  fail "earlyoom's effective ExecStart is not the packaged one; refusing to override it."
if /usr/bin/python3 -IB -c 'import sys; sys.path.insert(0, sys.argv[1]); import rules; sys.exit(0 if rules.admin_ignore(open("/etc/default/earlyoom", errors="replace").read(65536)) else 1)' "$src" 2>/dev/null; then
  printf '%s\n' 'Note: /etc/default/earlyoom already has its own --ignore. OOM Guard will leave it in charge'
  printf '%s\n' 'and add nothing until you remove it there.'
fi

targets=(/usr/lib/oomguard/rules.py /usr/lib/oomguard/oomguard-earlyoom-sync
         /etc/systemd/system/oomguard-earlyoom-sync.service /etc/systemd/system/oomguard-earlyoom-sync.timer
         /etc/systemd/system/earlyoom.service.d/50-oomguard.conf /etc/oomguard/earlyoom.env)
for dir in /usr/lib/oomguard /etc/oomguard /etc/systemd/system/earlyoom.service.d; do
  [[ ! -L $dir ]] || fail "Refusing symlink: $dir"
  [[ ! -e $dir || -d $dir ]] || fail "Refusing non-directory: $dir"
done
old_path=/etc/systemd/system/oomguard-earlyoom-sync.path  # 0.1.x watcher, replaced by the timer
migrate=()
for f in "${targets[@]}" "$old_path"; do
  [[ ! -L $f ]] || fail "Refusing symlink: $f"
  [[ -e $f ]] || continue
  ours "$f" && continue
  legacy_candidate "$f" && { migrate+=("$f"); continue; }
  fail "$f exists and was not written by OOM Guard; refusing to replace it."
done
confirm_legacy Replace "${migrate[@]}" || fail 'Left those files alone.'

for dir in /usr/lib/oomguard /etc/oomguard /etc/systemd/system/earlyoom.service.d; do
  install -d -m 0755 "$dir"
done
install -m 0644 "$src/rules.py" /usr/lib/oomguard/rules.py
install -m 0755 "$src/helper/oomguard-earlyoom-sync" /usr/lib/oomguard/oomguard-earlyoom-sync
install -m 0644 "$src/helper/oomguard-earlyoom-sync.service" /etc/systemd/system/oomguard-earlyoom-sync.service
install -m 0644 "$src/helper/oomguard-earlyoom-sync.timer" /etc/systemd/system/oomguard-earlyoom-sync.timer
install -m 0644 "$src/helper/earlyoom-dropin.conf" /etc/systemd/system/earlyoom.service.d/50-oomguard.conf
if [[ -e $old_path ]]; then
  systemctl disable --now oomguard-earlyoom-sync.path 2>/dev/null || true
  rm -f -- "$old_path"
fi
# A 0.1.x env file the user agreed to replace has no marker; the sync only
# ever replaces marked files, so start it fresh.
for f in "${migrate[@]}"; do
  [[ $f == /etc/oomguard/earlyoom.env ]] && rm -f -- "$f"
done

systemctl daemon-reload
# The sync writes the list and restarts earlyoom (only if it is running) so
# it picks up the drop-in; the timer keeps it current from then on.
systemctl start oomguard-earlyoom-sync.service
systemctl enable --now oomguard-earlyoom-sync.timer
printf '%s\n' 'OOM Guard is linked to earlyoom. Protected apps are now skipped by earlyoom too.'
