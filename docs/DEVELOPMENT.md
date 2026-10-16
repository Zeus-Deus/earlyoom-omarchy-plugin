# OOM Guard: development notes

Reference for contributors. Nothing here runs as part of the plugin.

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

Not verified: the memory-pressure kill path of systemd-oomd (only the swap path was
driven), multiple users with one earlyoom, and a current Omarchy dev build.
