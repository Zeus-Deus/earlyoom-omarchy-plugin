#!/usr/bin/python3
"""OOM Guard bridge: one JSON request on stdin, one JSON response on stdout, exit 0.

A stateless one-shot process: the panel starts it per request, it never stays
resident, never opens a network connection and never needs root.

Two different killers can take an app down on Omarchy:

* systemd-oomd (enabled by Omarchy) kills a whole app scope inside the user
  manager's app.slice. Protection = move the app's scopes into
  oomguard.slice, a sibling of app.slice that oomd does not watch. A plain
  call to the user's own systemd over D-Bus; no root.
* earlyoom (optional) kills single processes by score. Protection = its
  --ignore regex, which lives in a root-owned unit drop-in. This bridge only
  writes the user's list (~/.config/oomguard/protected.json); the root path
  unit from helper/install.sh turns that list into the drop-in.

Ops: status, kills, protect, unprotect, apply, restart_service.
"""
import fcntl
import json
import os
import re
import secrets
import select
import signal
import stat
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rules as R  # noqa: E402

MAX_REQUEST = 64 * 1024
MAX_CONFIG = 64 * 1024
GUARD_SLICE = "oomguard.slice"
RETURN_SLICE = "app-graphical.slice"
DROPIN_NAME = "50-oomguard.conf"
DROPIN_MARKER = "# Managed by OOM Guard (io.github.zeus-deus.oomguard)."
SYNC_TIMER_UNIT = "oomguard-earlyoom-sync.timer"
OLD_PATH_UNIT = "oomguard-earlyoom-sync.path"  # OOM Guard 0.1.x
KILL_DAYS_MAX = 30
# Hard end for one bridge run, above the panel's own 50 s deadline: a bridge
# the panel stopped waiting for cannot keep running.
DEADLINE_S = 55


def env(name, default):
    value = os.environ.get(name)
    return value if value else default


def home():
    return os.path.expanduser("~")


def config_dir():
    return env("OOMGUARD_CONFIG_DIR", os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.join(home(), ".config"), "oomguard"))


def state_dir():
    return env("OOMGUARD_STATE_DIR", os.path.join(os.environ.get("XDG_STATE_HOME") or os.path.join(home(), ".local", "state"), "oomguard"))


def systemd_user_dir():
    return env("OOMGUARD_SYSTEMD_USER_DIR", os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.join(home(), ".config"), "systemd", "user"))


def cgroup_root():
    return env("OOMGUARD_CGROUP_ROOT", "/sys/fs/cgroup")


def proc_root():
    return env("OOMGUARD_PROC_ROOT", "/proc")


def earlyoom_dropin():
    return env("OOMGUARD_EARLYOOM_DROPIN", "/etc/systemd/system/earlyoom.service.d/50-oomguard.conf")


# ---------------------------------------------------------------- io helpers

def run(argv, timeout=4, cap=2 * 1024 * 1024, errcap=4096):
    """Run a fixed argv (never a shell). Returns (code, stdout, stderr).

    Output is capped while it is read, not after: past `cap` bytes the child's
    whole process group is killed (exit 125), so a huge journal or client list
    never sits in this process's memory."""
    try:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    except FileNotFoundError:
        return 127, "", "not found"
    ofd, efd = p.stdout.fileno(), p.stderr.fileno()
    bufs = {ofd: [], efd: []}
    sizes = {ofd: 0, efd: 0}
    limits = {ofd: cap, efd: errcap}
    open_fds, deadline, status = set(bufs), time.monotonic() + timeout, None
    try:
        while open_fds:
            left = deadline - time.monotonic()
            if left <= 0:
                status = 124
                break
            ready, _, _ = select.select(list(open_fds), [], [], left)
            for fd in ready:
                chunk = os.read(fd, 65536)
                if not chunk:
                    open_fds.discard(fd)
                    continue
                room = limits[fd] - sizes[fd]
                if room > 0:
                    bufs[fd].append(chunk[:room])
                sizes[fd] += len(chunk)
                if fd == ofd and sizes[fd] > cap:
                    status = 125
                    open_fds.clear()
                    break
        if status is None:
            try:
                status = p.wait(max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                status = 124
    finally:
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
            p.wait()
        p.stdout.close()
        p.stderr.close()
    if status == 124:
        return 124, "", "timed out"
    return (status, b"".join(bufs[ofd]).decode("utf-8", "replace"),
            b"".join(bufs[efd]).decode("utf-8", "replace"))


def read_small(path, cap=65536):
    """Bounded read of a regular file. Never blocks on a FIFO or device."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file: " + path)
        chunks, total = [], 0
        while total <= cap:
            b = os.read(fd, min(65536, cap + 1 - total))
            if not b:
                break
            chunks.append(b)
            total += len(b)
        if total > cap:
            raise OSError("file too large: " + path)
        return b"".join(chunks).decode("utf-8", "replace")
    finally:
        os.close(fd)


def read_sys(path, cap=1 << 20):
    """procfs/cgroupfs report st_size 0; read them with a fixed cap."""
    try:
        with open(path, "rb") as f:
            return f.read(cap).decode("utf-8", "replace")
    except OSError:
        return ""


def read_int(path):
    try:
        return int(read_sys(path, 64).strip() or 0)
    except ValueError:
        return 0


def atomic_write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = "%s.tmp-%s" % (path, secrets.token_hex(4))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


clean = R.clean_text


# ---------------------------------------------------------------- the list

class mutation_lock:
    """One writer at a time across bridge processes: a bridge the panel gave
    up on (timeout) can still be running, and must not interleave with the
    next request's changes."""

    def __enter__(self):
        os.makedirs(state_dir(), exist_ok=True)
        self.fd = os.open(os.path.join(state_dir(), "lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        deadline = time.monotonic() + 15
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() > deadline:
                    os.close(self.fd)
                    raise RuntimeError("another OOM Guard change is still running")
                time.sleep(0.05)

    def __exit__(self, *exc):
        os.close(self.fd)
        return False


def rules_path():
    return os.path.join(config_dir(), "protected.json")


def load_rules():
    try:
        return R.parse_rules(read_small(rules_path(), MAX_CONFIG))
    except OSError:
        return []


def save_rules(rules):
    atomic_write(rules_path(), R.dump_rules(rules), 0o644)


# ---------------------------------------------------------------- cgroups

def user_manager_cgroup():
    """The user@UID.service cgroup this bridge (and the shell) runs under."""
    override = os.environ.get("OOMGUARD_USER_CGROUP")
    if override:
        return override
    for line in read_sys(os.path.join(proc_root(), "self", "cgroup")).splitlines():
        if line.startswith("0::"):
            m = re.match(r"^(.*?/user@\d+\.service)(/|$)", line[3:])
            if m:
                return m.group(1)
    uid = os.getuid()
    return "/user.slice/user-%d.slice/user@%d.service" % (uid, uid)


def pid_cgroup(pid):
    for line in read_sys(os.path.join(proc_root(), str(int(pid)), "cgroup"), 4096).splitlines():
        if line.startswith("0::"):
            return line[3:]
    return ""


def cg_fs(path):
    return os.path.join(cgroup_root(), path.lstrip("/"))


def cg_pids(path):
    return [int(t) for t in read_sys(os.path.join(cg_fs(path), "cgroup.procs")).split() if t.isdigit()]


def cg_mem(path):
    base = cg_fs(path)
    return read_int(os.path.join(base, "memory.current")), read_int(os.path.join(base, "memory.swap.current"))


def is_guarded(path):
    return ("/" + GUARD_SLICE + "/") in path


def movable(path, manager):
    """A transient app scope that systemd-oomd may pick. Services are never
    moved: pulling a service's main process out makes systemd restart it."""
    return path.startswith(manager + "/app.slice/") and path.endswith(".scope")


def comm_of(pid):
    return read_sys(os.path.join(proc_root(), str(int(pid)), "comm"), 64).strip()[:15]


def process_children():
    """ppid -> [pid] for the whole box, one /proc pass."""
    kids = {}
    try:
        names = os.listdir(proc_root())
    except OSError:
        return kids
    for name in names:
        if not name.isdigit():
            continue
        raw = read_sys(os.path.join(proc_root(), name, "stat"), 1024)
        end = raw.rfind(")")
        fields = raw[end + 2:].split() if end > 0 else []
        if len(fields) > 1 and fields[1].isdigit():
            kids.setdefault(int(fields[1]), []).append(int(name))
    return kids


def app_owned(path, manager):
    """Cgroups an app can own: app.slice (what oomd watches) and our guard.
    Never session.slice: that is Hyprland and the portals."""
    return path.startswith(manager + "/app.slice/") or path.startswith(manager + "/" + GUARD_SLICE + "/")


def start_of(pid):
    """Process start time in clock ticks since boot (field 22 of stat). With
    the pid it identifies one process; a reused pid gets a new start time."""
    raw = read_sys(os.path.join(proc_root(), str(int(pid)), "stat"), 1024)
    end = raw.rfind(")")
    fields = raw[end + 2:].split() if end > 0 else []
    return int(fields[19]) if len(fields) > 19 and fields[19].isdigit() else 0


def is_zombie(pid):
    raw = read_sys(os.path.join(proc_root(), str(int(pid)), "stat"), 1024)
    end = raw.rfind(")")
    return end > 0 and raw[end + 2:end + 3] == "Z"


def subtree(pid, kids, manager, limit=4000, stop=()):
    """Live processes of a window: its process and every descendant that is
    still in an app cgroup. Zombies are skipped: a launcher zombie reports the
    cgroup of whoever started it (Hyprland's service), not the app's.
    `stop` holds the pids of other windows: a GUI started from a terminal is
    its own window and never part of the terminal's tree, or the other way
    round."""
    seen, out, stack = set(), [], [pid]
    while stack and len(seen) < limit:
        p = stack.pop()
        if p in seen or (p != pid and p in stop):
            continue
        seen.add(p)
        if is_zombie(p):
            continue
        cg = pid_cgroup(p)
        if app_owned(cg, manager):
            out.append((p, cg))
        stack.extend(kids.get(p, []))
    return out


def app_cgroups(pid, kids, manager, limit=4000):
    """Cgroups of a window's process tree. Chromium-family and Electron apps
    move their main process into a scope of their own while the children stay
    in the launcher's scope, so one app can span two scopes."""
    out = []
    for _, cg in subtree(pid, kids, manager, limit):
        if cg not in out:
            out.append(cg)
    return out


def busctl_user(*args, timeout=6):
    return run(["busctl", "--user", "--timeout=5", "call", "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager"] + list(args), timeout=timeout)


def unit_token(text, limit=32):
    return (re.sub(r"[^A-Za-z0-9_]+", "_", str(text or "app")).strip("_") or "app")[:limit]


def move_pids(pids, dest_slice, label, leftovers):
    """Move `pids` into a new transient scope in `dest_slice`.

    StartTransientUnit adopts the PIDs it is given. `leftovers()` returns
    processes that should have moved but forked during the call; they are
    swept with AttachProcessesToUnit, which systemd only allows on a delegated
    scope, hence Delegate=yes."""
    pids = [p for p, st in pids if st and start_of(p) == st]  # (pid, start) pairs: skip reused pids
    if not pids:
        return {"ok": False, "error": "nothing left to move"}
    guard = dest_slice == GUARD_SLICE
    unit = "%s-%s-%s.scope" % ("oomguard" if guard else "app-oomguard-returned", unit_token(label), secrets.token_hex(4))
    props = (["PIDs", "au", str(len(pids))] + [str(p) for p in pids] +
             ["Slice", "s", dest_slice,
              "Delegate", "b", "true",
              "PartOf", "as", "1", "graphical-session.target",
              "After", "as", "1", "graphical-session.target",
              "Description", "s", clean(("OOM Guard: " if guard else "") + label, 80)])
    code, out, err = busctl_user("StartTransientUnit", "ssa(sv)a(sa(sv))", unit, "fail", "6", *props, "0")
    if code != 0:
        return {"ok": False, "error": clean(err or out or "StartTransientUnit failed", 160)}
    left = []
    for _ in range(3):
        left = [p for p, st in leftovers() if st and start_of(p) == st]
        if not left:
            break
        busctl_user("AttachProcessesToUnit", "ssau", unit, "/", str(len(left)), *[str(p) for p in left])
        time.sleep(0.05)
    return {"ok": True, "unit": unit, "moved": len(pids), "left": len(leftovers()) if left else 0}


def ident(procs):
    return [(p, start_of(p)) for p, _ in procs]


# ---------------------------------------------------------------- inventory

def window_clients():
    return [c for c in hypr_clients()
            if R.CLASS_RE.fullmatch(str(c.get("class") or c.get("initialClass") or ""))
            and isinstance(c.get("pid"), int) and not isinstance(c.get("pid"), bool) and c["pid"] > 1
            and R.WINDOW_RE.fullmatch(str(c.get("address") or ""))]


def public(apps):
    """Inventory without the internal per-process lists."""
    out = []
    for a in apps:
        a = {k: v for k, v in a.items() if k != "procs"}
        a["windowList"] = [{k: v for k, v in w.items() if k != "procs"} for w in a["windowList"]]
        out.append(a)
    return out


def hypr_clients():
    code, out, _ = run(["hyprctl", "-j", "clients"], timeout=3)
    if code != 0:
        return []
    try:
        data = json.loads(out)
    except ValueError:
        return []
    return [c for c in data if isinstance(c, dict)] if isinstance(data, list) else []


_DESKTOP_NAMES = None


def desktop_names():
    """lowercased desktop-file id and StartupWMClass -> Name (read once)."""
    global _DESKTOP_NAMES
    if _DESKTOP_NAMES is not None:
        return _DESKTOP_NAMES
    names = {}
    dirs = [os.environ.get("XDG_DATA_HOME") or os.path.join(home(), ".local", "share")]
    dirs += (os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share").split(":")
    for d in reversed(dirs):
        appdir = os.path.join(d, "applications")
        try:
            entries = sorted(os.listdir(appdir))[:3000]
        except OSError:
            continue
        for fn in entries:
            if not fn.endswith(".desktop"):
                continue
            try:
                text = read_small(os.path.join(appdir, fn), 256 * 1024)
            except OSError:
                continue
            name = wmclass = None
            section = False
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("["):
                    section = line == "[Desktop Entry]"
                elif section and line.startswith("Name=") and name is None:
                    name = line[5:]
                elif section and line.startswith("StartupWMClass="):
                    wmclass = line[15:]
            if name:
                names[fn[:-8].lower()] = name
                if wmclass:
                    names[wmclass.lower()] = name
    _DESKTOP_NAMES = names
    return names


def app_name(cls):
    names = desktop_names()
    key = str(cls or "").lower()
    for k in (key, key.rsplit(".", 1)[-1]):
        if k in names:
            return clean(names[k], 60)
    pretty = re.sub(r"[-_]+", " ", str(cls or "").rsplit(".", 1)[-1]).strip()
    return clean(pretty[:1].upper() + pretty[1:], 60) if pretty else "App"


def rss_of(pid):
    tok = read_sys(os.path.join(proc_root(), str(int(pid)), "statm"), 256).split()
    return int(tok[1]) * 4096 if len(tok) > 1 and tok[1].isdigit() else 0


def anon_of(pid):
    """Private memory of one process in bytes: resident (RssAnon) plus what
    is swapped out (VmSwap). Both count toward what OOM killers act on."""
    total = 0
    for line in read_sys(os.path.join(proc_root(), str(int(pid)), "status"), 8192).splitlines():
        if line.startswith("RssAnon:") or line.startswith("VmSwap:"):
            tok = line.split()
            total += int(tok[1]) * 1024 if len(tok) > 1 and tok[1].isdigit() else 0
    return total


def app_processes(procs, first):
    """(memory, names) for an app. Memory is the sum of each process's
    private resident memory: cgroup memory.current is wrong right after a
    protect, because pages stay charged to the cgroup that allocated them.
    Names are the processes that hold the memory, biggest first. earlyoom
    picks single processes, so the name it would kill is often a child (a
    browser renderer, the program inside a terminal), not the window's own."""
    by_name, total = {}, 0
    for pid, _ in procs[:2000]:
        name = comm_of(pid)
        anon = anon_of(pid)
        total += anon
        if name:
            by_name[name] = by_name.get(name, 0) + max(anon, rss_of(pid))
    ordered = [first] + [n for n, _ in sorted(by_name.items(), key=lambda kv: -kv[1]) if n != first]
    return total, R.clean_comms(ordered)


SHELL_COMMS = frozenset(R.GENERIC_COMMS | {"tmux", "screen", "zellij", "nu", "xonsh", "login", "foot", "footclient",
                                           "alacritty", "kitty", "ghostty", "wezterm-gui", "chrome_crashpad"})


def workspace_label(c):
    ws = c.get("workspace") if isinstance(c.get("workspace"), dict) else {}
    name = str(ws.get("name") or "")
    if name.startswith("special"):
        return "scratchpad"
    return "workspace " + clean(name or ws.get("id") or "?", 12)


def first_program(pid, kids, own, limit=400):
    """The program a terminal window is running: the shallowest descendant
    that is not a shell or launcher (foot -> bash -> herdr gives herdr)."""
    queue, seen = [pid], set()
    while queue and len(seen) < limit:
        p = queue.pop(0)
        if p in seen:
            continue
        seen.add(p)
        if p != pid and not is_zombie(p):
            name = comm_of(p)
            if name and name != own and name not in SHELL_COMMS:
                return name
        queue.extend(sorted(kids.get(p, [])))
    return ""


def window_info(c, procs, manager, shared, kids=None):
    """What the user needs to recognise one window: its title, workspace, the
    program that holds its memory (herdr inside a terminal), and that memory."""
    pid = c["pid"]
    own = comm_of(pid)
    by_name, mem = {}, 0
    for p, _ in procs:
        anon = anon_of(p)
        mem += anon
        name = comm_of(p)
        if name and name != own and name not in SHELL_COMMS:
            by_name[name] = by_name.get(name, 0) + anon
    running = [n for n, _ in sorted(by_name.items(), key=lambda kv: -kv[1])]
    top = first_program(pid, kids or {}, own) if kids is not None else (running[0] if running else "")
    if top and top in running:
        running.remove(top)
    if top:
        running.insert(0, top)
    cgs = [cg for _, cg in procs]
    return {
        "address": str(c.get("address") or ""), "pid": pid, "start": start_of(pid),
        "title": clean(c.get("title") or "", 80), "workspace": workspace_label(c),
        "running": clean(top, 15), "memBytes": mem,
        # earlyoom names for a window rule: what runs inside, not the terminal.
        "comms": R.clean_comms(running) or R.clean_comms([own]),
        "shared": shared, "guarded": bool(cgs) and all(is_guarded(cg) for cg in cgs),
        "units": sorted({cg.rsplit("/", 1)[-1] for cg in cgs})[:4],
    }


def app_inventory(manager, kids=None):
    """One row per window class, each with its windows."""
    kids = process_children() if kids is None else kids
    clients = window_clients()
    per_pid = {}
    for c in clients:
        per_pid[c["pid"]] = per_pid.get(c["pid"], 0) + 1
    window_pids = set(per_pid)
    rows = {}
    for c in clients:
        cls = str(c.get("class") or c.get("initialClass"))
        pid = c["pid"]
        procs = subtree(pid, kids, manager, stop=window_pids)
        if not procs:
            continue
        row = rows.get(cls)
        if row is None:
            row = rows[cls] = {"kind": "app", "key": cls, "name": app_name(cls), "comms": [],
                               "scopes": [], "windows": 0, "windowList": [], "procs": []}
        row["windows"] += 1
        info = window_info(c, procs, manager, per_pid[pid] > 1, kids)
        info["procs"] = procs
        row["windowList"].append(info)
        for pc in procs:
            if pc not in row["procs"]:
                row["procs"].append(pc)
        comm = comm_of(pid)
        if comm and comm not in row["comms"]:
            row["comms"].append(comm)
        for _, cg in procs:
            if cg not in row["scopes"]:
                row["scopes"].append(cg)
    out = []
    for row in rows.values():
        swap = sum(cg_mem(cg)[1] for cg in row["scopes"])
        mem, row["comms"] = app_processes(row["procs"], row["comms"][0] if row["comms"] else "")
        row["memBytes"], row["swapBytes"] = mem, swap
        # Exposed = this app's own processes still in app.slice. Never "every
        # pid of a cgroup": a terminal and a GUI it started can share one.
        row["exposed"] = sorted({cg.rsplit("/", 1)[-1] for _, cg in row["procs"] if movable(cg, manager)})[:16]
        row["guarded"] = any(is_guarded(cg) for _, cg in row["procs"]) and not row["exposed"]
        row["scopes"] = row["scopes"][:16]
        row["windowList"].sort(key=lambda w: -w["memBytes"])
        out.append(row)
    out.sort(key=lambda r: -r["memBytes"])
    return out


def dropin_path(unit):
    return os.path.join(systemd_user_dir(), unit + ".d", DROPIN_NAME)


def dropin_state(unit):
    try:
        text = read_small(dropin_path(unit), 4096)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "foreign"
    return "ours" if text.startswith(DROPIN_MARKER) else "foreign"


def service_inventory(manager):
    rows = []
    for slice_name in ("app.slice", "app.slice/app-graphical.slice", GUARD_SLICE):
        try:
            names = os.listdir(cg_fs(manager + "/" + slice_name))
        except OSError:
            continue
        for name in sorted(names):
            if not name.endswith(".service") or not R.UNIT_RE.fullmatch(name):
                continue
            cg = manager + "/" + slice_name + "/" + name
            pids = cg_pids(cg)
            if not pids:
                continue
            mem, swap = cg_mem(cg)
            rows.append({"kind": "service", "key": name, "name": name[:-8], "comms": R.clean_comms([comm_of(pids[0])]),
                         "memBytes": mem, "swapBytes": swap, "guarded": slice_name == GUARD_SLICE,
                         "dropin": dropin_state(name)})
    rows.sort(key=lambda r: -r["memBytes"])
    return rows


# ---------------------------------------------------------------- the killers

def systemctl_show(units, props):
    argv = ["systemctl", "show", "--no-pager", "--timestamp=unix"]
    for p in props:
        argv += ["-p", p]
    _, out, _ = run(argv + units, timeout=3)
    blocks, cur = [], {}
    for line in out.splitlines() + [""]:
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        k, _, v = line.partition("=")
        cur[k] = v
    return {b.get("Id", ""): b for b in blocks}


def oomd_state(manager, units):
    unit = units.get("systemd-oomd.service", {})
    active = unit.get("ActiveState") == "active"
    st = _oomd_state(manager, active)
    st.update(enabled=unit.get("UnitFileState") in ("enabled", "enabled-runtime", "static", "indirect", "alias"),
              byOmarchy=os.path.exists(omarchy_oomd_conf()), since=since_of(unit) if active else 0)
    return st


def _oomd_state(manager, active):
    code, out, _ = run(["oomctl"], timeout=2, cap=512 * 1024)
    text = out if code == 0 else ""
    num = lambda pat: (lambda m: float(m.group(1)) if m else None)(re.search(pat, text))  # noqa: E731
    monitored = sorted(set(re.findall(r"Path:\s*(\S+)", text)))
    guard = manager + "/" + GUARD_SLICE
    return {
        "active": active,
        "readable": code == 0,
        "swapLimit": num(r"Swap Used Limit:\s*([\d.]+)%"),
        "pressureLimit": num(r"Default Memory Pressure Limit:\s*([\d.]+)%"),
        "watchesApps": (manager + "/app.slice") in monitored,
        # The guard is only real while no monitored cgroup contains it.
        "guardWatched": any(guard == p or guard.startswith(p.rstrip("/") + "/") for p in monitored),
    }


def pacman_db():
    return env("OOMGUARD_PACMAN_DB", "/var/lib/pacman/local")


def package_info(name):
    """Version, install time and reason of an installed package, read from
    pacman's own database (no pacman process, no root)."""
    try:
        entries = os.listdir(pacman_db())
    except OSError:
        return None
    for e in entries:
        if not e.startswith(name + "-") or not re.match(re.escape(name) + r"-[^-]+-[^-]+$", e):
            continue
        try:
            text = read_small(os.path.join(pacman_db(), e, "desc"), 65536)
        except OSError:
            return None
        fields, key = {}, None
        for line in text.splitlines():
            if line.startswith("%") and line.endswith("%"):
                key = line.strip("%")
            elif key and line:
                fields.setdefault(key, line)
        date = fields.get("INSTALLDATE", "")
        return {"version": clean(fields.get("VERSION", ""), 40),
                "installedAt": int(date) if date.isdigit() else 0,
                "explicit": fields.get("REASON", "0") == "0"}
    return None


def helper_rules():
    return env("OOMGUARD_HELPER_RULES", "/usr/lib/oomguard/rules.py")


def omarchy_oomd_conf():
    return env("OOMGUARD_OMARCHY_OOMD_CONF", "/usr/lib/systemd/user/app.slice.d/10-oomd.conf")


def since_of(unit):
    """Unix time a unit last became active (systemctl --timestamp=unix)."""
    v = unit.get("ActiveEnterTimestamp", "")
    return int(v[1:]) if v.startswith("@") and v[1:].isdigit() else 0


def earlyoom_limits(args):
    """earlyoom's own thresholds from its argv (defaults 10 % / 10 %)."""
    mem, swap = 10.0, 10.0
    for i, a in enumerate(args[:-1]):
        nxt = args[i + 1].split(",")[0]
        try:
            if a == "-m":
                mem = float(nxt)
            elif a == "-s":
                swap = float(nxt)
        except ValueError:
            pass
    return {"memPercent": mem, "swapPercent": swap,
            "absolute": any(a in ("-M", "-S") for a in args)}


def earlyoom_state(rules, units):
    unit = units.get("earlyoom.service", {})
    mine = set(R.earlyoom_names(rules))
    args = []
    pid = unit.get("MainPID", "0")
    if pid.isdigit() and int(pid) > 0:
        args = read_sys(os.path.join(proc_root(), pid, "cmdline"), 8192).split("\0")
    running = ""
    for i, a in enumerate(args[:-1]):
        if a == "--ignore":
            running = args[i + 1]  # earlyoom keeps the last --ignore it parses
    active = unit.get("ActiveState") == "active"
    timer = units.get(SYNC_TIMER_UNIT, {})
    old = units.get(OLD_PATH_UNIT, {})
    linked = os.path.exists(earlyoom_dropin()) and (timer.get("LoadState") == "loaded" or old.get("LoadState") == "loaded")
    # The root helper keeps its own copy of rules.py. After a plugin update it
    # may not know newer rule kinds and silently skip them; a 0.1.x link also
    # still uses the old file watcher.
    current = timer.get("LoadState") == "loaded"
    if linked and current:
        try:
            current = read_small(helper_rules(), 262144) == read_small(os.path.join(HERE, "rules.py"), 262144)
        except OSError:
            current = False
    installed = unit.get("LoadState") == "loaded"
    have = R.names_in_regex(running)
    return {"installed": installed, "active": active,
            "failed": unit.get("ActiveState") == "failed",
            "enabled": unit.get("UnitFileState") in ("enabled", "enabled-runtime", "static", "indirect", "alias"),
            "since": since_of(unit) if active else 0,
            "package": package_info("earlyoom") if installed else None,
            "limits": earlyoom_limits(args) if active else None,
            "linked": linked, "helperCurrent": bool(current) if linked else True,
            "syncWatching": timer.get("ActiveState") == "active" or old.get("ActiveState") == "active",
            # Other users' names may be in the regex too: applied = all of mine are.
            "applied": bool(linked and active and mine <= have),
            "names": sorted(mine), "runningIgnore": clean(running, 400)}


def meminfo():
    vals = {}
    for line in read_sys(os.path.join(proc_root(), "meminfo"), 16384).splitlines():
        k, _, rest = line.partition(":")
        tok = rest.split()
        if tok and tok[0].isdigit():
            vals[k] = int(tok[0]) * 1024
    return {"total": vals.get("MemTotal", 0), "available": vals.get("MemAvailable", 0),
            "swapTotal": vals.get("SwapTotal", 0), "swapFree": vals.get("SwapFree", 0)}


# ---------------------------------------------------------------- scope names

def scopes_path():
    return os.path.join(state_dir(), "scopes.json")


def load_scope_names():
    try:
        data = json.loads(read_small(scopes_path(), 512 * 1024))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def remember_scopes(apps):
    """systemd-oomd's kill line names only the scope (app-Hyprland-gtk\\x2dlaunch-6c0f….scope).
    Remember which app (and, for a terminal, which program) lived where, so
    the kill list can say "Foot · herdr" instead of a launcher hash."""
    known = load_scope_names()
    changed = False
    now = int(time.time())
    for a in apps:
        labels = {}
        for cg in a["scopes"]:
            labels[cg.rsplit("/", 1)[-1]] = a["name"]
        for w in a.get("windowList") or []:
            if w.get("running"):
                for unit in w.get("units") or []:
                    labels[unit] = a["name"] + " · " + w["running"]
        for unit, label in labels.items():
            entry = known.get(unit)
            if not isinstance(entry, dict) or entry.get("name") != label:
                known[unit] = {"name": label, "t": now}
                changed = True
    if changed:
        items = sorted(known.items(), key=lambda kv: kv[1].get("t", 0) if isinstance(kv[1], dict) else 0)[-400:]
        try:
            atomic_write(scopes_path(), json.dumps(dict(items)) + "\n", 0o600)
        except OSError:
            pass


def launched_label(cmd):
    """Readable name for the command uwsm started a scope with."""
    argv = cmd.split()
    if not argv:
        return ""
    prog = os.path.basename(argv[0])
    if prog == "gtk-launch" and len(argv) > 1:
        return app_name(argv[1][:-8] if argv[1].endswith(".desktop") else argv[1])
    if prog in ("xdg-terminal-exec", "omarchy-launch-terminal", "foot", "alacritty", "kitty", "ghostty"):
        inner = argv[argv.index("-e") + 1] if "-e" in argv[:-1] else ""
        return "Terminal" + (" · " + clean(os.path.basename(inner), 30) if inner else "")
    return app_name(prog)


def launcher_map(since):
    """scope unit -> what was launched in it, from uwsm's own journal lines."""
    out = {}
    for e in journal_json(["journalctl", "--no-pager", "-q", "-o", "json", "--since", since,
                           "_UID=%d" % os.getuid(), "-t", "uwsm_app-daemon", "-g", "sent: exec"], 2000):
        msg = str(e.get("MESSAGE") or "")
        m = re.search(r"--unit=([^' ]+)", msg)
        if not m or " -- " not in msg:
            continue
        out[m.group(1)] = clean(msg.split(" -- ", 1)[1].replace("'", ""), 200)
    return out


def scope_label(unit, known, launched=None):
    entry = known.get(unit)
    if isinstance(entry, dict) and entry.get("name"):
        return clean(entry["name"], 60)
    if launched and unit in launched:
        label = launched_label(launched[unit])
        if label:
            return label
    u = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), unit)
    m = re.match(r"^app-([A-Za-z0-9.]+?)-\d+\.scope$", u)
    if m:
        return app_name(m.group(1))
    m = re.match(r"^app-[Hh]yprland-(.+?)-[0-9a-f]{8}\.scope$", u)
    if m:
        return {"xdg-terminal-exec": "Terminal", "gtk-launch": "An app"}.get(m.group(1), clean(m.group(1), 60))
    return clean(u, 60)


# ---------------------------------------------------------------- ops

def which(name):
    for d in (os.environ.get("PATH") or "/usr/bin").split(":"):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def op_status(req):
    manager = user_manager_cgroup()
    rules = load_rules()
    apps = app_inventory(manager)
    units = systemctl_show(["systemd-oomd.service", "earlyoom.service", SYNC_TIMER_UNIT, OLD_PATH_UNIT],
                           ["Id", "LoadState", "ActiveState", "UnitFileState", "MainPID", "ActiveEnterTimestamp"])
    remember_scopes(apps)
    return {"ok": True, "rules": rules, "apps": public(apps), "services": service_inventory(manager),
            "oomd": oomd_state(manager, units),
            "earlyoom": earlyoom_state(rules, units), "mem": meminfo(),
            "terminalAvailable": bool(which("omarchy-launch-floating-terminal-with-presentation"))}


def rule_matches(rule, w):
    return w["address"] == rule["key"] and w["pid"] == rule["pid"] and (not rule.get("start") or w["start"] == rule["start"])


def wanted_procs(rules, apps, only=None):
    """(rule, [(pid, cgroup)]) for every running window a rule covers."""
    out = []
    for r in rules:
        if only is not None and not (r["kind"] == only[0] and r["key"] == only[1]):
            continue
        if r["kind"] == "app":
            row = next((a for a in apps if a["key"] == r["key"]), None)
            if row:
                out.append((r, row["procs"]))
        elif r["kind"] == "window":
            for a in apps:
                for w in a["windowList"]:
                    if rule_matches(r, w):
                        out.append((r, w["procs"]))
    return out


def window_alive(rule, apps):
    return any(rule_matches(rule, w) for a in apps for w in a["windowList"])


def move_set(procs, dest, label, manager):
    """Move these processes of the user's own apps, re-reading them right
    before each step. Only transient app scopes are ever moved; a service's
    processes never leave their service."""
    if dest == GUARD_SLICE:
        pick = lambda cg: movable(cg, manager)  # noqa: E731
    else:
        pick = lambda cg: cg.startswith(manager + "/" + GUARD_SLICE + "/") and cg.endswith(".scope")  # noqa: E731
    ids = [(p, st) for p, st in ident(procs) if st and pick(pid_cgroup(p))]
    if not ids:
        return {"ok": True, "moved": 0}
    pids = {p for p, _ in ids}

    def leftovers():
        kids = process_children()
        more = []
        for p in list(pids):
            for c in kids.get(p, []):
                if c not in pids and pick(pid_cgroup(c)):
                    more.append((c, start_of(c)))
        return more

    return move_pids(ids, dest, label, leftovers)


def apply_rules(rules, manager, only=None):
    """Move every running window a rule covers out of app.slice. Rules for
    single windows that closed are dropped from the list."""
    moved, errors = [], []
    apps = app_inventory(manager)
    for r, procs in wanted_procs(rules, apps, only):
        res = move_set(procs, GUARD_SLICE, r["name"], manager)
        if not res.get("ok"):
            errors.append(dict(res, key=r["key"], name=r["name"]))
        elif res.get("moved"):
            moved.append(dict(res, key=r["key"], name=r["name"]))
    if only is None:
        gone = [r for r in rules if r["kind"] == "window" and not window_alive(r, apps)]
        live = refreshed_comms(rules, apps)
        if gone or live != rules:
            keep = {(g["kind"], g["key"]) for g in gone}
            save_rules([r for r in live if (r["kind"], r["key"]) not in keep])
    if moved:
        apps = app_inventory(manager)
    return moved, errors, apps


def refreshed_comms(rules, apps):
    """Rules with earlyoom names taken from what runs now, so a terminal that
    started another program, or an app with a new helper process, stays
    covered. Names only change while the app or window is open."""
    out = []
    for r in rules:
        live = None
        if r["kind"] == "app":
            row = next((a for a in apps if a["key"] == r["key"]), None)
            live = row["comms"] if row else None
        elif r["kind"] == "window":
            w = next((w for a in apps for w in a["windowList"] if rule_matches(r, w)), None)
            live = w["comms"] if w else None
        if live and live != r["comms"]:
            r = dict(r, comms=R.clean_comms(live))
        out.append(r)
    return out


def op_apply(req):
    manager = user_manager_cgroup()
    with mutation_lock():
        moved, errors, apps = apply_rules(load_rules(), manager)
    if apps:
        remember_scopes(apps)
    return {"ok": True, "moved": moved, "errors": errors}


def op_protect(req):
    kind = req.get("kind")
    key = str(req.get("key") or "")
    manager = user_manager_cgroup()
    if kind == "app":
        if not R.CLASS_RE.fullmatch(key):
            return {"ok": False, "error": "invalid app"}
        row = next((a for a in app_inventory(manager) if a["key"] == key), None)
        name, comms = (row["name"], row["comms"]) if row else (app_name(key), [])
    elif kind == "window":
        if not R.WINDOW_RE.fullmatch(key):
            return {"ok": False, "error": "invalid window"}
        win = None
        for row in app_inventory(manager):
            for w in row["windowList"]:
                if w["address"] == key:
                    win, app = w, row
        if win is None:
            return {"ok": False, "error": "that window is closed"}
        # The panel sends the identity it showed; a window that closed and was
        # replaced at the same address in between is refused, not protected.
        if req.get("pid") != win["pid"] or req.get("start") != win["start"]:
            return {"ok": False, "error": "that window changed; try again"}
        if win["shared"]:
            return {"ok": False, "error": "this window shares its process with other windows; protect the app instead"}
        label = win["running"] or (win["title"][:30] if win["title"] else "window")
        name, comms = "%s · %s" % (app["name"], label), win["comms"]
    elif kind == "service":
        if not R.UNIT_RE.fullmatch(key):
            return {"ok": False, "error": "invalid service"}
        if dropin_state(key) == "foreign":
            return {"ok": False, "error": "%s already has a %s that OOM Guard did not write" % (key, DROPIN_NAME)}
        row = next((s for s in service_inventory(manager) if s["key"] == key), None)
        name, comms = key[:-8], (row["comms"] if row else [])
    else:
        return {"ok": False, "error": "invalid kind"}
    with mutation_lock():
        rules = [r for r in load_rules() if not (r["kind"] == kind and r["key"] == key)]
        if len(rules) >= R.MAX_RULES:
            return {"ok": False, "error": "too many protected entries (max %d)" % R.MAX_RULES}
        rule = {"kind": kind, "key": key, "name": name, "comms": comms}
        if kind == "window":
            rule["pid"], rule["start"] = win["pid"], win["start"]
        rules.append(R.normalize_rule(rule))
        result = {"ok": True, "kind": kind, "key": key, "name": name, "errors": []}
        if kind == "service":
            atomic_write(dropin_path(key), DROPIN_MARKER + "\n"
                         "# Runs this service outside app.slice, the slice systemd-oomd watches.\n"
                         "# Takes effect the next time the service starts.\n"
                         "[Service]\nSlice=" + GUARD_SLICE + "\n", 0o644)
            code, _, err = run(["systemctl", "--user", "daemon-reload"], timeout=15)
            if code != 0:
                os.unlink(dropin_path(key))
                return {"ok": False, "error": clean("systemd did not reload: " + (err or str(code)), 160)}
            save_rules(rules)
            result["restartNeeded"] = True
            return result
        save_rules(rules)
        moved, errors, _ = apply_rules(rules, manager, only=(kind, key))
        result.update(moved=moved, errors=errors)
    return result


def op_unprotect(req):
    kind = req.get("kind")
    key = str(req.get("key") or "")
    if kind not in ("app", "service", "window"):
        return {"ok": False, "error": "invalid kind"}
    if kind == "service" and not R.UNIT_RE.fullmatch(key):
        return {"ok": False, "error": "invalid service"}
    manager = user_manager_cgroup()
    with mutation_lock():
        before = load_rules()
        target = next((r for r in before if r["kind"] == kind and r["key"] == key), None)
        rest = [r for r in before if r is not target]
        result = {"ok": True, "kind": kind, "key": key, "errors": []}
        if kind == "service":
            if dropin_state(key) == "ours":
                os.unlink(dropin_path(key))
                try:
                    os.rmdir(os.path.dirname(dropin_path(key)))
                except OSError:
                    pass
                code, _, err = run(["systemctl", "--user", "daemon-reload"], timeout=15)
                if code != 0:
                    result["errors"].append({"error": clean("systemd did not reload: " + (err or str(code)), 160)})
                result["restartNeeded"] = True
            save_rules(rest)
            return result
        save_rules(rest)
        if target is None:
            return result
        apps = app_inventory(manager)
        # Processes another remaining rule still covers stay protected.
        still = {p for _, procs in wanted_procs(rest, apps) for p, _ in procs}
        for _, procs in wanted_procs([target], apps):
            back = [pc for pc in procs if pc[0] not in still]
            res = move_set(back, RETURN_SLICE, target["name"], manager)
            if not res.get("ok"):
                result["errors"].append(dict(res, key=key, name=target["name"]))
    return result


def op_restart_service(req):
    key = str(req.get("key") or "")
    if not R.UNIT_RE.fullmatch(key):
        return {"ok": False, "error": "invalid service"}
    if not any(s["key"] == key for s in service_inventory(user_manager_cgroup())):
        return {"ok": False, "error": "not a running user service"}
    code, _, err = run(["systemctl", "--user", "restart", key], timeout=40)
    if code != 0:
        return {"ok": False, "error": clean(err or "restart failed", 160)}
    return {"ok": True, "key": key}


def journal_json(argv, limit):
    """Newest `limit` matching entries, newest first. journalctl itself stops
    after `limit` records (-n with -r), and only the needed fields come back,
    so the read is small however large the journal is."""
    _, out, _ = run(argv + ["-r", "-n", str(int(limit)), "--output-fields=MESSAGE,USER_UNIT,UNIT,__REALTIME_TIMESTAMP"],
                    timeout=10, cap=2 * 1024 * 1024)
    rows = []
    for line in out.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict):
            rows.append(e)
    return rows


def op_kills(req):
    try:
        days = max(1, min(KILL_DAYS_MAX, int(req.get("days") or 7)))
    except (TypeError, ValueError):
        days = 7
    since = "-%dd" % days
    known = load_scope_names()
    launched = launcher_map(since)
    kills = []
    for e in journal_json(["journalctl", "--no-pager", "-q", "-o", "json", "--since", since,
                           "_UID=%d" % os.getuid(), "_COMM=systemd", "-g", "systemd-oomd killed"], 500):
        unit = str(e.get("USER_UNIT") or e.get("UNIT") or "")
        m = re.search(r"killed (\d+) process", str(e.get("MESSAGE") or ""))
        kills.append({"by": "systemd-oomd", "name": scope_label(unit, known, launched), "unit": clean(unit, 120),
                      "processes": int(m.group(1)) if m else None,
                      "t": int(e.get("__REALTIME_TIMESTAMP") or 0) // 1000000})
    for e in journal_json(["journalctl", "--no-pager", "-q", "-o", "json", "--since", since,
                           "-u", "earlyoom.service", "-g", "sending SIG(TERM|KILL) to process"], 500):
        m = re.search(r'sending (SIG\w+) to process \d+ uid (\d+) "([^"]*)".*?VmRSS (\d+) MiB', str(e.get("MESSAGE") or ""))
        if not m or int(m.group(2)) != os.getuid():
            continue
        kills.append({"by": "earlyoom", "name": clean(m.group(3), 40), "signal": m.group(1),
                      "rssBytes": int(m.group(4)) * 1024 * 1024,
                      "t": int(e.get("__REALTIME_TIMESTAMP") or 0) // 1000000})
    kills.sort(key=lambda k: k["t"], reverse=True)
    counts = {"systemd-oomd": 0, "earlyoom": 0}
    last = {"systemd-oomd": 0, "earlyoom": 0}
    for k in kills:
        counts[k["by"]] += 1
        last[k["by"]] = max(last[k["by"]], k["t"])
    # Counts cover the newest 500 records of each killer; more is reported as "500+".
    capped = {"systemd-oomd": counts["systemd-oomd"] >= 500, "earlyoom": counts["earlyoom"] >= 500}
    return {"ok": True, "days": days, "total": len(kills), "counts": counts, "capped": capped,
            "last": last, "kills": kills[:60]}


def op_focus(req):
    """Bring one window to the front so the user can see which one a row is."""
    address = str(req.get("address") or "")
    if not R.WINDOW_RE.fullmatch(address):
        return {"ok": False, "error": "invalid window"}
    if not any(str(c.get("address") or "") == address for c in hypr_clients()):
        return {"ok": False, "error": "that window is closed"}
    # Fixed Lua literal; the address matched ^0x[0-9a-f]{1,16}$ above.
    code, out, err = run(["hyprctl", "dispatch", 'hl.dsp.focus({ window = "address:%s" })' % address], timeout=3)
    if code != 0 or "not found" in (out + err):
        return {"ok": False, "error": clean(err or out or "could not focus", 120)}
    return {"ok": True, "address": address}


OPS = {"status": op_status, "kills": op_kills, "protect": op_protect, "unprotect": op_unprotect,
       "apply": op_apply, "restart_service": op_restart_service, "focus": op_focus}


def main():
    signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
    signal.alarm(DEADLINE_S)
    raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
    try:
        if len(raw) > MAX_REQUEST:
            raise ValueError("request too large")
        req = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(req, dict):
            raise ValueError("request must be an object")
        fn = OPS.get(req.get("op"))
        resp = fn(req) if fn else {"ok": False, "error": "unknown op"}
    except Exception as exc:  # one response, always
        resp = {"ok": False, "error": clean("%s: %s" % (type(exc).__name__, exc), 200)}
    sys.stdout.write(json.dumps(resp, separators=(",", ":")))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
