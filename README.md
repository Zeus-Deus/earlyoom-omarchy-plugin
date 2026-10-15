# OOM Guard for Omarchy

Choose the apps and services that must not be killed when your memory runs out.

| Apps | Services | Kills |
|---|---|---|
| ![Apps](docs/images/apps.png) | ![Services](docs/images/services.png) | ![Kills](docs/images/kills.png) |

## Install

```bash
omarchy plugin add https://github.com/Zeus-Deus/earlyoom-omarchy-plugin.git --enable --yes
```

That is all Omarchy's own OOM killer (systemd-oomd) needs. If you also run
earlyoom, which Omarchy does not ship, click **Link…** in the panel once, or run:

```bash
sudo bash ~/.config/omarchy/plugins/io.github.zeus-deus.oomguard/helper/install.sh
```

Update: `omarchy plugin update io.github.zeus-deus.oomguard`, then `omarchy-restart-shell`.
Re-run the helper's `install.sh` only when `helper/` or `rules.py` changed.

## What it does

Click the shield in the bar. Every open window and every user service has a
switch. Turn it on and that app is skipped the next time memory runs out.

- **Apps**: the app's windows are protected straight away, and so are windows it
  opens later. An app you protected keeps its switch even while it is closed.
- **Services**: user services such as Syncthing or a voice daemon. Protection
  takes effect when the service restarts; press `r` on the row to do that now.
- **Kills**: what systemd-oomd and earlyoom killed in the last 30 days, with a
  switch to protect the app that was killed.

The line under the title tells you which killers are running and whether your
list reaches all of them.

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

**earlyoom** picks single processes by name and score. The panel keeps your
list in `~/.config/oomguard/protected.json`. The optional helper is a root
systemd path unit that turns that list into earlyoom's `--ignore` option and
restarts earlyoom when the list changes. It also always adds the desktop itself
(Hyprland, the Omarchy shell and Xwayland). Without that, earlyoom's next
choice after your protected apps is often the shell: in testing, it killed the
bar eleven times in two minutes until Omarchy stopped restarting it.

## Limits

- A protected app can still be the one using up memory. Then systemd-oomd
  picks something else, and if nothing else helps, the kernel's own OOM killer
  decides. Protect the apps you work in, not everything.
- earlyoom only matches process names. Protecting Obsidian adds `electron`,
  which also covers other Electron apps with that name, and protecting a
  terminal app adds `foot`, which covers every foot window.
- Windows of a protected app that open while the shell is not running are
  protected a few seconds after the shell starts.

## Keyboard

`j`/`k` move · `Enter` switch on/off · `1` `2` `3` or `Tab` change tab ·
`r` restart the selected service · `L` link earlyoom · `Esc` close.
Switching protection off asks first. Cancel is the default.

## Security

- The panel never runs anything as root. The only root step is the helper's
  `install.sh`, which you start yourself. **Link…** opens Omarchy's terminal
  with the fixed command `sudo bash <plugin>/helper/install.sh`, and you type
  your own password there.
- The root helper reads each user's list as a regular file, without following
  symlinks, and with a size limit. It accepts only names made of
  `A-Z a-z 0-9 . _ + -`, at most 15 characters each, and refuses interpreters
  such as `python3` or `bash`. A list can only add names for earlyoom to skip.
  It cannot stop earlyoom or change its other options.
- The plugin makes no network connections: no telemetry and no update check.
- Every process the shell starts goes through a fixed output cap.

## Uninstall

```bash
sudo bash ~/.config/omarchy/plugins/io.github.zeus-deus.oomguard/helper/uninstall.sh   # only if you linked earlyoom
omarchy plugin remove io.github.zeus-deus.oomguard --yes
```

Apps that are open stay in `oomguard.slice` until you close them. Service
drop-ins written by the plugin stay until you switch those services off in the
panel before removing it, or delete them yourself
(`~/.config/systemd/user/*.service.d/50-oomguard.conf`).
`~/.config/oomguard/` keeps your list.

## Development

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## License

MIT
