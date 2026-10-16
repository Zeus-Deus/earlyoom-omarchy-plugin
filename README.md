# OOM Guard for Omarchy

When your memory runs out, something gets killed. OOM Guard lets you pick
what must survive: whole apps, single windows (like the terminal running your
agents) and user services.

| Apps and windows | Both killers | Services |
|---|---|---|
| ![Apps](docs/images/apps.png) | ![Killers](docs/images/killers.png) | ![Services](docs/images/services.png) |

## Install

```bash
omarchy plugin add https://github.com/Zeus-Deus/earlyoom-omarchy-plugin.git --enable --yes
```

Click the shield in the bar, then switch on what you want to keep.

## What it does

- **Apps**: protect an app and all its windows, now and later.
- **Windows**: each window shows its workspace, its title and what runs in it
  (`herdr`, `nvim`, …). Protect just that one. Press `f` to jump to it.
- **Services**: protect a user service. It applies on the next restart (`r`).
- **Killers**: see both OOM killers side by side and what each one killed.
  Turn earlyoom on or off, link it, install or remove it from here.

## Two killers

| | systemd-oomd | earlyoom |
|---|---|---|
| Comes from | Omarchy, on by default | You (`omarchy pkg add earlyoom`) |
| Kills | one whole app | the biggest process |
| Works on | your desktop apps | everything, servers too |

They work fine together, and OOM Guard keeps one list for both. Protecting
from systemd-oomd needs no password. For earlyoom, press **Link…** once and
type your password in the terminal that opens. earlyoom is one service for
the whole machine, so on a computer with several accounts, every account's
list applies to everyone ([details](docs/DEVELOPMENT.md#security-details)).

## Keys

`j`/`k` move · `Enter` switch · `Tab` next tab · `f` show window ·
`w` fold windows · `r` restart service · `Esc` close

## Good to know

- If a protected app is the one eating all the memory, something else is
  killed first. As a last resort the kernel decides.
- earlyoom only knows process names, so protecting a window also protects
  every process with that name.

## Security

The panel never runs anything as root. earlyoom actions open Omarchy's
terminal with one fixed command each (`sudo bash <plugin>/helper/install.sh`,
`sudo systemctl enable|disable --now earlyoom.service`,
`omarchy pkg add|drop earlyoom`), and you type your own password there.
No network connections, no telemetry. Full details in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Remove

```bash
sudo bash ~/.config/omarchy/plugins/io.github.zeus-deus.oomguard/helper/uninstall.sh   # only if you linked earlyoom
omarchy plugin remove io.github.zeus-deus.oomguard --yes
```

Your list stays in `~/.config/oomguard/`. Switch services off in the panel
before removing; that deletes the `50-oomguard.conf` drop-ins OOM Guard wrote
and nothing else.

## License

MIT
