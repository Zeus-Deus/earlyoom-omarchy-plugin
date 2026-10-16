# OOM Guard: development notes

Reference for contributors and reviewers. Nothing here runs as part of the plugin.

## How it works

Omarchy turns on **systemd-oomd**. When memory or swap runs out it kills one
whole app, but only apps inside `app.slice`, the group that every app you
launch lands in. The compositor and the shell live in `session.slice`, so they
are never picked.

Protecting an app moves its processes into a group of their own,
`oomguard.slice`, next to `app.slice`. systemd-oomd does not watch it. This is
a normal call to your own systemd user manager and needs no password. A
protected service gets a small drop-in, `~/.config/systemd/user/<unit>.d/50-oomguard.conf`,
with `Slice=oomguard.slice`.

### Two killers, one list

| | systemd-oomd | earlyoom |
|---|---|---|
| Comes from | Omarchy turns it on | You install it (`omarchy pkg add earlyoom`) |
| Acts when | swap is over 90 % full, or memory stalls for 20 s | free memory and free swap both fall under 10 % |
| Kills | one whole app | the single biggest process |
| Covers | apps launched in your desktop session | every process, on desktops and headless servers |

They do not conflict. On a desktop with a large swap file, systemd-oomd
usually acts first; earlyoom is the backstop that also works on servers and
over SSH, where Omarchy's setup does not apply. OOM Guard keeps one list and
applies it to both.

**earlyoom** picks single processes by name and score. The panel keeps your
list in `~/.config/oomguard/protected.json`. The optional helper is a root
systemd path unit that turns that list into earlyoom's `--ignore` option and
restarts earlyoom when the list changes. It also always adds the desktop itself
(Hyprland, the Omarchy shell and Xwayland). Without that, earlyoom's next
choice after your protected apps is often the shell: in testing, it killed the
bar eleven times in two minutes until Omarchy stopped restarting it.

### Limits

- A protected app can still be the one using up memory. Then systemd-oomd
  picks something else, and if nothing else helps, the kernel's own OOM killer
  decides. Protect the apps you work in, not everything.
- earlyoom only matches process names. Protecting Obsidian adds `electron`,
  which also covers other Electron apps with that name, and protecting a
  terminal app adds `foot`, which covers every foot window. A single window
  adds the name of the program inside it (`herdr`), so for earlyoom it covers
  every process with that name.
- A window that shares its process with other windows (a `foot --server`
  setup, or several windows of one browser) cannot be protected alone; protect
  the app instead. The panel says so on the row.
- Windows of a protected app that open while the shell is not running are
  protected a few seconds after the shell starts.

## Security details

- The panel never runs anything as root. **Link…**, **Turn on/off…**,
  **Install…** and **Remove…** open Omarchy's terminal with one fixed
  command each (`sudo bash <plugin>/helper/install.sh`,
  `sudo systemctl enable|disable --now earlyoom.service`,
  `omarchy pkg add|drop earlyoom`), and you type your own password there.
  None of those commands is built from window titles, settings or the list.
- The root helper reads each user's list as a regular file, without following
  symlinks, and with a size limit. It accepts only names made of
  `A-Z a-z 0-9 . _ + -`, at most 15 characters each, and refuses interpreters
  such as `python3` or `bash`. A list can only add names for earlyoom to skip.
  It cannot stop earlyoom or change its other options.
- The plugin makes no network connections: no telemetry and no update check.
- Every process the shell starts goes through a fixed output cap.

## Files

- `Panel.qml`: bar button, `KeyboardPanel` with three tabs (Apps with per-window rows, Services, Killers with one card per OOM killer), confirm dialog and IPC verbs (`open`, `close`, `tab`, `cursor`, `activate`, `key`, `status`).
  Uses eager children, not the newer lazy `content:`, so it loads on stable Omarchy 4.0.x.
- `Service.qml`: the bridge `Process`, request queue and deadline. It also listens to
  Hyprland `openwindow` events and runs `apply` (debounced) so new windows of protected
  apps move out of `app.slice`. It is loaded whenever the bar widget is.
- `Model.js`: pure helpers with no Qt imports, loaded by Node in a `vm` context.
- `bridge.py`: one JSON request on stdin, one response on stdout, exit 0.
  Ops: `status`, `kills`, `protect`, `unprotect`, `apply`, `restart_service`, `focus`. Rule kinds: `app`, `service`, `window` (address + pid; dropped when the window closes).
- `rules.py`: the list parser and the earlyoom regex builder. It is shared by the bridge
  and the root helper, so the panel's "applied" check and the root side build the same
  string.
- `helper/`: the optional root earlyoom link: a path unit, a oneshot sync service, an
  earlyoom drop-in, and install/uninstall scripts.

## Rules

1. Only transient `*.scope` units under `app.slice` are moved. A `*.service` is never
   moved: pulling its main process out makes systemd consider it dead. Services get a
   `Slice=oomguard.slice` drop-in carrying `DROPIN_MARKER`. A drop-in without the marker
   is never written over or deleted.
2. Moving uses `StartTransientUnit` (PIDs, `Slice=oomguard.slice`, `Delegate=yes`), then
   `AttachProcessesToUnit` for processes forked during the move. systemd refuses the
   attach on scopes that are not delegated.
3. App inventory walks the process tree from each Hyprland client PID. Chromium-family
   apps and Electron apps put their main process in a scope of their own, while children
   stay in the launcher's scope. Session-slice cgroups and zombies are skipped: a launcher
   zombie reports Hyprland's cgroup.
4. Per-app memory is the sum of each process's `RssAnon + VmSwap`, not `memory.current`.
   Pages stay charged to the cgroup that allocated them, so after a move the new scope
   reads near 0.
5. earlyoom gets one anchored regex, `^(a|b|…)$`, built only from
   `[A-Za-z0-9._+-]{1,15}` names. `.` and `+` are bracketed, and there are no
   backslashes or spaces, because the value passes through an `EnvironmentFile` and an
   unbraced `$OOMGUARD_ARGS`. Interpreters and launchers are refused (`GENERIC_COMMS`).
   The session (`SESSION_COMMS`) is always included.
6. No TextInput-based kit controls, no bare `Color.`, and every `Process` command goes
   through `Model.boundedArgv`. `tests/model.test.js` checks all three.
7. The confirm dialog's keys are handled on a wrapper `Item` above the blocked
   `PanelKeyCatcher`. Handling them on the catcher itself let the Return that opened the
   dialog also answer it (as Cancel), so the dialog never appeared.

## Gates

```bash
node --test tests/*.test.js
uv run --python /usr/bin/python3 --with pytest pytest -q -p no:cacheprovider tests/
omarchy plugin validate .
d=$(mktemp -d) && ln -s /usr/share/omarchy/shell "$d/qs" && /usr/lib/qt6/bin/qmllint -I "$d" -I /usr/lib/qt6/qml Panel.qml Service.qml
```

The bridge tests use fake `/proc` and cgroup trees, set through the `OOMGUARD_*`
environment overrides. They never touch the real ones.

## Verified in an Omarchy 4.0.3 VM (Quickshell 0.3.1, systemd 261)

- Installed with `omarchy plugin add` and loaded with no `qs log` errors.
- Down + Enter in the panel protected Obsidian. All of its processes moved to
  `oomguard.slice`, and the list was saved.
- systemd-oomd swap kill, unprotected: a memory hog in a foot window was killed
  ("systemd-oomd killed 2 process(es)").
- The same hog protected through the panel survived 45 s past the kill threshold.
  oomd logged candidates but marked none. Protected Obsidian survived both runs.
- A new window of an app already on the list was moved automatically within 6 s.
- After **Link…**, earlyoom ran with `--ignore` set to the protected names plus the
  session. The protected hog survived again; earlyoom killed unprotected Files and
  Chromium instead.
- Before the session names were added, earlyoom killed the Omarchy shell 11 times in
  2 minutes until `omarchy-launch-shell` gave up. After the fix the shell kept its PID
  through the same test.
- Service: Enter on `omarchy-fcitx5` wrote the drop-in, and `r` restarted it into
  `oomguard.slice` (new MainPID).
- A shell restart re-applied the list: Chromium, added while the shell was down, was
  moved within seconds of startup.
- Unprotect: Enter opens the dialog with Cancel selected. Enter cancels. Right + Enter
  moves the app back to `app-graphical.slice`.
- Single window: three foot windows (a `herdr` process, `nvim`, `btop`). Enter on the
  `herdr` row moved only that window's processes into `oomguard.slice`; the other two
  stayed in `app.slice`. A second, unprotected foot window then filled memory:
  earlyoom killed it, `herdr` survived. Protecting a window through real keys took
  effect in 14 of 15 tries, including 8 of 8 after a VM reboot. One early try did not
  take and could not be reproduced.
- A protected window that itself held memory at 96 % swap for 3 minutes was not
  touched by systemd-oomd.
- `f` focused the window on another workspace; `w` folded and unfolded an app's
  windows without changing protection. Closing a window dropped its rule.
- Killers tab: after a plugin update the earlyoom link was reported out of date;
  Relink (Enter on the card) opened Omarchy's terminal, ran the helper, and earlyoom's
  `--ignore` then included `herdr`.

Not verified: the memory-pressure kill path of systemd-oomd (only the swap path was
driven), multiple users with one earlyoom, and a current Omarchy dev build.
