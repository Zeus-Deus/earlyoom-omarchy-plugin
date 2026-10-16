"""Bridge and rules tests. Fake /proc and cgroup trees; never the real ones.

Run: uv run --python /usr/bin/python3 --with pytest pytest -q -p no:cacheprovider tests/
"""
import importlib.util
import json
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import rules as R  # noqa: E402

MANAGER = "/user.slice/user-1000.slice/user@1000.service"


def load_bridge():
    spec = importlib.util.spec_from_file_location("bridge", os.path.join(ROOT, "bridge.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def env(tmp_path, monkeypatch):
    for d in ("cfg", "state", "sd", "cg", "proc"):
        (tmp_path / d).mkdir()
    monkeypatch.setenv("OOMGUARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("OOMGUARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("OOMGUARD_SYSTEMD_USER_DIR", str(tmp_path / "sd"))
    monkeypatch.setenv("OOMGUARD_CGROUP_ROOT", str(tmp_path / "cg"))
    monkeypatch.setenv("OOMGUARD_PROC_ROOT", str(tmp_path / "proc"))
    monkeypatch.setenv("OOMGUARD_USER_CGROUP", MANAGER)
    monkeypatch.setenv("OOMGUARD_EARLYOOM_DROPIN", str(tmp_path / "earlyoom-dropin.conf"))
    return tmp_path


def add_cgroup(root, rel, pids, mem=0, swap=0):
    d = root / "cg" / (MANAGER + "/" + rel).lstrip("/")
    d.mkdir(parents=True, exist_ok=True)
    (d / "cgroup.procs").write_text("".join("%d\n" % p for p in pids))
    (d / "memory.current").write_text("%d\n" % mem)
    (d / "memory.swap.current").write_text("%d\n" % swap)
    return MANAGER + "/" + rel


def add_proc(root, pid, ppid, comm, cgroup, rss_pages=100):
    d = root / "proc" / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    (d / "comm").write_text(comm + "\n")
    (d / "cgroup").write_text("0::%s\n" % cgroup)
    (d / "stat").write_text("%d (%s) S %d 0 0\n" % (pid, comm, ppid))
    (d / "statm").write_text("1000 %d 0 0 0 0 0\n" % rss_pages)
    (d / "status").write_text("Name:\t%s\nRssAnon:\t%d kB\nVmSwap:\t%d kB\n" % (comm, rss_pages * 2, rss_pages * 2))


# ---------------------------------------------------------------- rules.py

def test_regex_is_anchored_and_needs_no_backslashes():
    rules = [{"kind": "app", "key": "a", "comms": ["chromium", "obsidian"]},
             {"kind": "service", "key": "x.service", "comms": ["my.app+x"]}]
    rx = R.earlyoom_regex(rules)
    assert rx == "^(Hyprland|Xwayland|chromium|my[.]app[+]x|obsidian|quickshell)$"
    assert "\\" not in rx and " " not in rx
    pat = re.compile(rx)
    assert pat.search("chromium") and not pat.search("chromium-x") and not pat.search("xchromium")
    assert pat.search("my.app+x") and not pat.search("myXapp+x")


@pytest.mark.parametrize("bad", ["python3", "bash", "a b", "x;rm", "$(id)", "a\\b", "", "a" * 16, "ev\u202egnp"])
def test_unsafe_or_generic_names_never_reach_earlyoom(bad):
    rules = R.parse_rules(json.dumps({"protected": [{"kind": "app", "key": "k", "comms": [bad]}]}))
    assert R.earlyoom_names(rules) == []
    assert R.earlyoom_regex(rules) == R.earlyoom_regex([])


def test_parse_rules_drops_garbage_and_duplicates():
    raw = json.dumps({"protected": [
        {"kind": "app", "key": "chromium", "comms": ["chromium"]},
        {"kind": "app", "key": "chromium", "comms": ["x"]},
        {"kind": "service", "key": "not-a-unit", "comms": []},
        {"kind": "root", "key": "x"},
        "nope",
        {"kind": "app", "key": "old", "comm": "legacy"},
    ]})
    out = R.parse_rules(raw)
    assert [(r["kind"], r["key"], r["comms"]) for r in out] == [("app", "chromium", ["chromium"]), ("app", "old", ["legacy"])]
    assert R.parse_rules("{not json") == []
    assert R.parse_rules(json.dumps({"protected": [{"kind": "app", "key": "k%d" % i} for i in range(500)]})).__len__() == R.MAX_RULES


def test_helper_uses_the_same_regex_builder():
    src = open(os.path.join(ROOT, "helper", "oomguard-earlyoom-sync")).read()
    assert "import rules as R" in src and "R.earlyoom_regex(" in src
    assert "rules.py" in open(os.path.join(ROOT, "helper", "install.sh")).read()


def test_helper_env_line_round_trips_through_systemd_rules():
    # The drop-in expands $OOMGUARD_ARGS unbraced: systemd splits it on
    # whitespace into exactly ["--ignore", regex].
    rules = [{"kind": "app", "key": "a", "comms": ["chromium", "Obsidian"]}]
    value = "--ignore " + R.earlyoom_regex(rules)
    assert value.split() == ["--ignore", "^(Hyprland|Obsidian|Xwayland|chromium|quickshell)$"]


def test_the_desktop_session_is_always_shielded_from_earlyoom():
    pat = re.compile(R.earlyoom_regex([]))
    for name in ("Hyprland", "quickshell", "Xwayland"):
        assert pat.search(name)
    assert not pat.search("Hyprlandx") and not pat.search("chromium")


# ---------------------------------------------------------------- bridge

def test_inventory_follows_a_browser_across_two_scopes(env, monkeypatch):
    b = load_bridge()
    launcher = add_cgroup(env, "app.slice/app-graphical.slice/app-Hyprland-chromium-a63f68f7.scope", [20, 21], mem=300 << 20)
    own = add_cgroup(env, "app.slice/app-org.chromium.Chromium-10.scope", [10], mem=100 << 20)
    add_proc(env, 10, 1, "chromium", own)
    add_proc(env, 20, 10, "chromium", launcher, rss_pages=5000)
    add_proc(env, 21, 10, "chrome_crashpad", launcher)
    monkeypatch.setattr(b, "hypr_clients", lambda: [{"class": "chromium", "pid": 10, "address": "0xa1", "title": "about:blank", "workspace": {"id": 1, "name": "1"}}])
    monkeypatch.setattr(b, "desktop_names", lambda: {"chromium": "Chromium"})
    apps = b.app_inventory(MANAGER)
    assert len(apps) == 1
    a = apps[0]
    # private memory of the three processes (100 + 5000 + 100 pages), not cgroup charges
    assert a["name"] == "Chromium" and a["memBytes"] == 5200 * 4096
    assert sorted(a["exposed"]) == sorted(["app-org.chromium.Chromium-10.scope", "app-Hyprland-chromium-a63f68f7.scope"])
    assert a["comms"][0] == "chromium" and not a["guarded"]


def test_session_slice_and_zombies_never_count_as_part_of_an_app(env, monkeypatch):
    b = load_bridge()
    own = add_cgroup(env, "app.slice/app-graphical.slice/app-Hyprland-nautilus-d990889f.scope", [15], mem=170 << 20)
    hypr = add_cgroup(env, "session.slice/wayland-wm@hyprland.desktop.service", [2], mem=900 << 20)
    add_proc(env, 15, 2, "nautilus", own)
    add_proc(env, 16, 15, "uwsm-app", hypr)
    (env / "proc" / "16" / "stat").write_text("16 (uwsm-app) Z 15 0 0\n")
    add_proc(env, 17, 15, "Hyprland", hypr)  # even a live child there is not the app's
    monkeypatch.setattr(b, "hypr_clients", lambda: [{"class": "org.gnome.Nautilus", "pid": 15, "address": "0xb2", "workspace": {"id": 2, "name": "2"}}])
    monkeypatch.setattr(b, "desktop_names", lambda: {})
    a = b.app_inventory(MANAGER)[0]
    assert a["scopes"] == [own] and a["memBytes"] == 100 * 4096
    assert "Hyprland" not in a["comms"]


def test_protect_app_moves_every_scope_and_saves_the_list(env, monkeypatch):
    b = load_bridge()
    own = add_cgroup(env, "app.slice/app-org.chromium.Chromium-10.scope", [10])
    add_proc(env, 10, 1, "chromium", own)
    monkeypatch.setattr(b, "hypr_clients", lambda: [{"class": "chromium", "pid": 10, "address": "0xa1", "title": "about:blank", "workspace": {"id": 1, "name": "1"}}])
    monkeypatch.setattr(b, "desktop_names", lambda: {})
    calls = []

    def fake_move(src, dest, label):
        calls.append((src, dest, label))
        return {"ok": True, "unit": "oomguard-x.scope", "moved": 1, "left": 0}

    monkeypatch.setattr(b, "move_cgroup", fake_move)
    res = b.op_protect({"kind": "app", "key": "chromium"})
    assert res["ok"] and calls == [(own, b.GUARD_SLICE, "Chromium")]
    saved = json.loads((env / "cfg" / "protected.json").read_text())
    assert saved["protected"][0]["key"] == "chromium" and saved["protected"][0]["comms"] == ["chromium"]


def test_services_are_never_moved_only_given_a_dropin(env, monkeypatch):
    b = load_bridge()
    svc = add_cgroup(env, "app.slice/syncthing.service", [30], mem=1 << 20)
    add_proc(env, 30, 1, "syncthing", svc)
    monkeypatch.setattr(b, "move_cgroup", lambda *a: pytest.fail("a service must not be moved"))
    monkeypatch.setattr(b, "run", lambda argv, **k: (0, "", ""))
    res = b.op_protect({"kind": "service", "key": "syncthing.service"})
    assert res["ok"] and res["restartNeeded"]
    dropin = env / "sd" / "syncthing.service.d" / "50-oomguard.conf"
    text = dropin.read_text()
    assert text.startswith(b.DROPIN_MARKER) and "Slice=oomguard.slice" in text
    assert b.op_unprotect({"kind": "service", "key": "syncthing.service"})["ok"]
    assert not dropin.exists()


def test_a_foreign_dropin_is_left_alone(env, monkeypatch):
    b = load_bridge()
    d = env / "sd" / "x.service.d"
    d.mkdir(parents=True)
    (d / "50-oomguard.conf").write_text("[Service]\nMemoryMax=1G\n")
    res = b.op_protect({"kind": "service", "key": "x.service"})
    assert not res["ok"] and "did not write" in res["error"]
    b.op_unprotect({"kind": "service", "key": "x.service"})
    assert (d / "50-oomguard.conf").read_text() == "[Service]\nMemoryMax=1G\n"


@pytest.mark.parametrize("req", [{"op": "protect", "kind": "service", "key": "../../etc/passwd"},
                                 {"op": "protect", "kind": "service", "key": "a.service/../../x.service"},
                                 {"op": "protect", "kind": "app", "key": "a/b"},
                                 {"op": "restart_service", "key": "sshd"},
                                 {"op": "unprotect", "kind": "root", "key": "x"}])
def test_bad_keys_are_refused(env, req):
    b = load_bridge()
    res = b.OPS[req["op"]](req)
    assert res["ok"] is False


def test_restart_only_touches_a_running_user_service(env, monkeypatch):
    b = load_bridge()
    seen = []
    monkeypatch.setattr(b, "run", lambda argv, **k: seen.append(argv) or (0, "", ""))
    assert b.op_restart_service({"key": "notmine.service"})["ok"] is False
    add_cgroup(env, "app.slice/voxtype.service", [40])
    add_proc(env, 40, 1, "voxtype", MANAGER + "/app.slice/voxtype.service")
    assert b.op_restart_service({"key": "voxtype.service"})["ok"] is True
    assert seen == [["systemctl", "--user", "restart", "voxtype.service"]]


def test_earlyoom_applied_reads_the_running_argv(env, monkeypatch):
    b = load_bridge()
    (env / "earlyoom-dropin.conf").write_text("x")
    rules = [{"kind": "app", "key": "a", "comms": ["chromium"]}]
    d = env / "proc" / "77"
    d.mkdir(parents=True)
    (d / "cmdline").write_bytes(b"/usr/bin/earlyoom\0-r\0003600\0--ignore\0" + R.earlyoom_regex(rules).encode() + b"\0")
    units = {"earlyoom.service": {"LoadState": "loaded", "ActiveState": "active", "MainPID": "77"},
             b.SYNC_PATH_UNIT: {"LoadState": "loaded", "ActiveState": "active"}}
    st = b.earlyoom_state(rules, units)
    assert st["applied"] and st["linked"] and st["names"] == ["chromium"]
    st = b.earlyoom_state(rules + [{"kind": "app", "key": "b", "comms": ["obsidian"]}], units)
    assert not st["applied"]


def test_oomd_guard_watched_is_detected(monkeypatch):
    b = load_bridge()
    text = ("Swap Used Limit: 90.00%\nDefault Memory Pressure Limit: 50.00%\n"
            "Swap Monitored CGroups:\n\tPath: " + MANAGER + "/app.slice\n")
    monkeypatch.setattr(b, "run", lambda argv, **k: (0, text, ""))
    st = b._oomd_state(MANAGER, True)
    assert st["watchesApps"] and not st["guardWatched"] and st["swapLimit"] == 90.0
    monkeypatch.setattr(b, "run", lambda argv, **k: (0, text + "\tPath: " + MANAGER + "\n", ""))
    assert b._oomd_state(MANAGER, True)["guardWatched"]


def test_scope_labels_for_kill_lines():
    b = load_bridge()
    b.desktop_names = lambda: {"chromium": "Chromium", "codemux": "CodeMux"}
    assert b.scope_label("app-Hyprland-xdg\\x2dterminal\\x2dexec-7d74f234.scope", {}) == "Terminal"
    assert b.scope_label("app-org.chromium.Chromium-824779.scope", {}) == "Chromium"
    assert b.scope_label("x.scope", {"x.scope": {"name": "Brave"}}) == "Brave"
    launched = {"app-Hyprland-gtk\\x2dlaunch-6c0fdda6.scope": "gtk-launch codemux.desktop",
                "app-Hyprland-xdg\\x2dterminal\\x2dexec-1.scope": "xdg-terminal-exec -e herdr"}
    assert b.scope_label("app-Hyprland-gtk\\x2dlaunch-6c0fdda6.scope", {}, launched) == "CodeMux"
    assert b.scope_label("app-Hyprland-xdg\\x2dterminal\\x2dexec-1.scope", {}, launched) == "Terminal · herdr"


def test_kills_only_reports_this_users_earlyoom_victims(env, monkeypatch):
    b = load_bridge()
    uid = os.getuid()
    lines = [
        json.dumps({"MESSAGE": 'sending SIGTERM to process 5 uid %d "chromium": oom_score 900, oom_score_adj 200, VmRSS 2048 MiB, cmdline "x"' % uid, "__REALTIME_TIMESTAMP": "2000000000"}),
        json.dumps({"MESSAGE": 'sending SIGTERM to process 6 uid 0 "rootthing": oom_score 900, oom_score_adj 0, VmRSS 1 MiB, cmdline "x"', "__REALTIME_TIMESTAMP": "3000000000"}),
    ]
    oomd = [json.dumps({"MESSAGE": "app-Hyprland-gtk\\x2dlaunch-6c0fdda6.scope: systemd-oomd killed 12 process(es) in this unit.",
                        "USER_UNIT": "app-Hyprland-gtk\\x2dlaunch-6c0fdda6.scope", "__REALTIME_TIMESTAMP": "1000000000"})]

    def fake_run(argv, **k):
        if "uwsm_app-daemon" in argv:
            return (0, "", "")
        return (0, "\n".join(oomd if "_COMM=systemd" in argv else lines), "")

    monkeypatch.setattr(b, "run", fake_run)
    res = b.op_kills({"days": 3})
    assert [k["name"] for k in res["kills"]] == ["chromium", "An app"]
    assert res["kills"][1]["processes"] == 12
    assert res["counts"] == {"systemd-oomd": 1, "earlyoom": 1}


def test_bridge_process_always_answers_with_json(env):
    for payload in [b"", b"[]", b"{bad", b'{"op":"nope"}', b"x" * 70000]:
        p = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "bridge.py")], input=payload,
                           capture_output=True, timeout=20, env=dict(os.environ))
        assert p.returncode == 0
        assert json.loads(p.stdout)["ok"] is False


# ---------------------------------------------------------------- windows

def terminal_fixture(env, monkeypatch, b, shared=False):
    """Two foot windows in one scope each; window A runs herdr, B runs vim."""
    sa = add_cgroup(env, "app.slice/app-graphical.slice/app-Hyprland-foot-aaaaaaaa.scope", [50, 51, 52, 53])
    sb = add_cgroup(env, "app.slice/app-graphical.slice/app-Hyprland-foot-bbbbbbbb.scope", [60, 61, 62])
    add_proc(env, 50, 1, "foot", sa)
    add_proc(env, 51, 50, "bash", sa)
    add_proc(env, 52, 51, "herdr", sa, rss_pages=9000)
    add_proc(env, 53, 52, "herdr", sa, rss_pages=200)
    add_proc(env, 60, 1, "foot", sb)
    add_proc(env, 61, 60, "bash", sb)
    add_proc(env, 62, 61, "vim", sb)
    clients = [{"class": "foot", "pid": 50, "address": "0xaa", "title": "agents", "workspace": {"id": 4, "name": "4"}},
               {"class": "foot", "pid": 60, "address": "0xbb", "title": "notes", "workspace": {"id": 2, "name": "2"}}]
    if shared:
        clients[1]["pid"] = 50
    monkeypatch.setattr(b, "hypr_clients", lambda: clients)
    monkeypatch.setattr(b, "desktop_names", lambda: {"foot": "Foot"})
    return sa, sb


def test_each_terminal_window_shows_what_runs_in_it(env, monkeypatch):
    b = load_bridge()
    terminal_fixture(env, monkeypatch, b)
    app = b.app_inventory(MANAGER)[0]
    assert app["windows"] == 2
    by = {w["address"]: w for w in app["windowList"]}
    assert by["0xaa"]["running"] == "herdr" and by["0xaa"]["workspace"] == "workspace 4"
    assert by["0xaa"]["title"] == "agents" and by["0xaa"]["comms"][0] == "herdr"
    assert by["0xbb"]["running"] == "vim"
    assert app["windowList"][0]["address"] == "0xaa"  # biggest first


def test_protecting_one_window_moves_only_that_window(env, monkeypatch):
    b = load_bridge()
    terminal_fixture(env, monkeypatch, b)
    moved = []
    monkeypatch.setattr(b, "move_pids", lambda pids, dest, label, left: moved.append((sorted(pids), dest, label)) or
                        {"ok": True, "moved": len(pids), "left": 0})
    res = b.op_protect({"kind": "window", "key": "0xaa"})
    assert res["ok"] and res["name"] == "Foot · herdr"
    assert moved == [([50, 51, 52, 53], b.GUARD_SLICE, "Foot · herdr")]
    saved = json.loads((env / "cfg" / "protected.json").read_text())["protected"]
    assert saved == [{"kind": "window", "key": "0xaa", "name": "Foot · herdr", "comms": ["herdr"], "pid": 50}]
    assert R.earlyoom_names(R.parse_rules(json.dumps({"protected": saved}))) == ["herdr"]


def test_a_window_that_shares_its_process_is_refused(env, monkeypatch):
    b = load_bridge()
    terminal_fixture(env, monkeypatch, b, shared=True)
    monkeypatch.setattr(b, "move_pids", lambda *a: pytest.fail("must not move a shared process"))
    res = b.op_protect({"kind": "window", "key": "0xaa"})
    assert not res["ok"] and "protect the app instead" in res["error"]


def test_window_rules_die_with_their_window(env, monkeypatch):
    b = load_bridge()
    terminal_fixture(env, monkeypatch, b)
    rules = [{"kind": "window", "key": "0xaa", "name": "Foot · herdr", "comms": ["herdr"], "pid": 50},
             {"kind": "window", "key": "0xcc", "name": "gone", "comms": [], "pid": 999},
             {"kind": "window", "key": "0xbb", "name": "reused address", "comms": [], "pid": 12345}]
    (env / "cfg" / "protected.json").write_text(R.dump_rules(rules))
    monkeypatch.setattr(b, "move_pids", lambda pids, *a: {"ok": True, "moved": len(pids), "left": 0})
    res = b.op_apply({})
    assert [m["key"] for m in res["moved"]] == ["0xaa"]
    left = json.loads((env / "cfg" / "protected.json").read_text())["protected"]
    assert [r["key"] for r in left] == ["0xaa"]


def test_window_rules_need_a_valid_address_and_pid():
    assert R.parse_rules(json.dumps({"protected": [
        {"kind": "window", "key": "0xaa", "pid": 50},
        {"kind": "window", "key": "0xaa; rm", "pid": 50},
        {"kind": "window", "key": "0xbb"},
        {"kind": "window", "key": "0xcc", "pid": True}]})) == [
        {"kind": "window", "key": "0xaa", "name": "0xaa", "comms": [], "pid": 50}]


def test_focus_only_dispatches_a_fixed_command_for_an_open_window(env, monkeypatch):
    b = load_bridge()
    monkeypatch.setattr(b, "hypr_clients", lambda: [{"address": "0xaa"}])
    calls = []
    monkeypatch.setattr(b, "run", lambda argv, **k: calls.append(argv) or (0, "ok", ""))
    assert not b.op_focus({"address": '0xaa" }) os.execute("x'})["ok"]
    assert not b.op_focus({"address": "0xbb"})["ok"]
    assert b.op_focus({"address": "0xaa"})["ok"]
    assert calls == [["hyprctl", "dispatch", 'hl.dsp.focus({ window = "address:0xaa" })']]


# ---------------------------------------------------------------- both killers

def test_earlyoom_package_and_limits_are_read_without_root(env, monkeypatch):
    b = load_bridge()
    db = env / "pacman"
    (db / "earlyoom-1.9.0-1").mkdir(parents=True)
    (db / "earlyoom-1.9.0-1" / "desc").write_text("%NAME%\nearlyoom\n\n%VERSION%\n1.9.0-1\n\n%INSTALLDATE%\n1784995596\n\n")
    (db / "earlyoom-extra-2-1").mkdir()
    monkeypatch.setenv("OOMGUARD_PACMAN_DB", str(db))
    info = b.package_info("earlyoom")
    assert info == {"version": "1.9.0-1", "installedAt": 1784995596, "explicit": True}
    assert b.earlyoom_limits(["earlyoom", "-m", "5,2", "-s", "15"]) == {"memPercent": 5.0, "swapPercent": 15.0, "absolute": False}
    assert b.earlyoom_limits(["earlyoom"]) == {"memPercent": 10.0, "swapPercent": 10.0, "absolute": False}


def test_oomd_reports_whether_omarchy_turned_it_on(env, monkeypatch):
    b = load_bridge()
    conf = env / "10-oomd.conf"
    monkeypatch.setenv("OOMGUARD_OMARCHY_OOMD_CONF", str(conf))
    monkeypatch.setattr(b, "run", lambda argv, **k: (0, "", ""))
    units = {"systemd-oomd.service": {"ActiveState": "active", "UnitFileState": "enabled", "ActiveEnterTimestamp": "@1791973195"}}
    st = b.oomd_state(MANAGER, units)
    assert st["active"] and st["enabled"] and not st["byOmarchy"] and st["since"] == 1791973195
    conf.write_text("[Slice]\n")
    assert b.oomd_state(MANAGER, units)["byOmarchy"]


def test_a_link_from_an_older_plugin_version_is_reported(env, monkeypatch):
    b = load_bridge()
    dropin = env / "50-oomguard.conf"
    dropin.write_text("[Service]\n")
    helper = env / "helper-rules.py"
    monkeypatch.setenv("OOMGUARD_EARLYOOM_DROPIN", str(dropin))
    monkeypatch.setenv("OOMGUARD_HELPER_RULES", str(helper))
    units = {"earlyoom.service": {"LoadState": "loaded", "ActiveState": "active", "MainPID": "0"},
             b.SYNC_PATH_UNIT: {"LoadState": "loaded", "ActiveState": "active"}}
    helper.write_text("old")
    assert b.earlyoom_state([], units)["helperCurrent"] is False
    helper.write_text(open(os.path.join(b.HERE, "rules.py")).read())
    assert b.earlyoom_state([], units)["helperCurrent"] is True
