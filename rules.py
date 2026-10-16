# Managed by OOM Guard (io.github.zeus-deus.oomguard).
"""The protected list: one parser and one earlyoom regex builder.

Shared by bridge.py (runs as the desktop user inside the shell) and by
helper/earlyoom-sync (runs as root, installed by helper/install.sh). Keeping
both on this one file is what guarantees the panel's "applied" check and the
root side build the same string. Pure stdlib, no I/O beyond what callers pass.
"""
import json
import re

MARKER = "# Managed by OOM Guard (io.github.zeus-deus.oomguard)."
MAX_RULES = 64
MAX_COMMS = 4
# Per user. The root helper unions users' names without truncating, so one
# user can never push another user's names out.
MAX_IGNORE_NAMES = 32
# earlyoom matches /proc/<pid>/comm, which the kernel truncates to 15 bytes.
# The class is deliberately narrow: no whitespace, quotes, backslashes or
# regex syntax, so the generated value survives a systemd EnvironmentFile and
# an unbraced $VAR expansion as exactly one word.
# Every pattern is used with fullmatch(): "$" alone also matches before a
# trailing newline.
COMM_RE = re.compile(r"[A-Za-z0-9._+-]{1,15}")
UNIT_RE = re.compile(r"[A-Za-z0-9:_.\\@-]{1,200}\.service")
CLASS_RE = re.compile(r"[^\x00-\x1f\x7f/]{1,128}")
# A Hyprland window address. A window rule lives only as long as the window.
WINDOW_RE = re.compile(r"0x[0-9a-f]{1,16}")
# Versioned interpreters (python3.13, perl5.40, node22): same reason as below.
INTERPRETER_RE = re.compile(r"(python|perl|ruby|node|php|lua|luajit|tclsh|wish|java|pypy|bash|zsh|ksh|sh)[0-9.]*")
# Interpreters, shells and launchers: ignoring one of these would protect
# every script on the machine, not the app the user picked.
# The desktop session itself. earlyoom's stock --avoid covers only init,
# systemd, Xorg and sshd, so once the apps a user protected are skipped its
# next pick is often the Omarchy shell (quickshell) or the compositor:
# measured in the VM, it killed the shell 11 times in two minutes until the
# shell's supervisor gave up and the bar was gone. Omarchy keeps these out of
# systemd-oomd's reach by putting them in session.slice; the earlyoom link
# does the same.
SESSION_COMMS = ("Hyprland", "quickshell", "Xwayland")
GENERIC_COMMS = frozenset("""
bash sh zsh fish dash env sleep cat python python3 node nodejs deno bun java perl ruby
systemd systemd-run uwsm-app xdg-terminal-ex gtk-launch setsid sudo su timeout nohup
""".split())


def clean_text(value, limit=80):
    text = re.sub(r"[\x00-\x1f\x7f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]+", " ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def ok_comm(c):
    return (isinstance(c, str) and COMM_RE.fullmatch(c) is not None and c not in GENERIC_COMMS
            and INTERPRETER_RE.fullmatch(c) is None)


def clean_comms(values):
    out = []
    for c in values or []:
        c = str(c or "")
        if ok_comm(c) and c not in out:
            out.append(c)
        if len(out) >= MAX_COMMS:
            break
    return out


def normalize_rule(item):
    if not isinstance(item, dict):
        return None
    kind = item.get("kind")
    key = str(item.get("key") or "")
    if kind == "app":
        if not CLASS_RE.fullmatch(key):
            return None
    elif kind == "service":
        if not UNIT_RE.fullmatch(key):
            return None
    elif kind == "window":
        if not WINDOW_RE.fullmatch(key):
            return None
    else:
        return None
    comms = item.get("comms")
    if comms is None and item.get("comm"):
        comms = [item.get("comm")]
    rule = {"kind": kind, "key": key, "name": clean_text(item.get("name") or key, 60),
            "comms": clean_comms(comms if isinstance(comms, list) else [])}
    if kind == "window":
        # Window addresses are reused after a window closes; the pid pins the
        # rule to the one window it was made for.
        pid, start = item.get("pid"), item.get("start", 0)
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
            return None
        if not isinstance(start, int) or isinstance(start, bool) or start < 0:
            return None
        rule["pid"] = pid
        # The process start time (clock ticks since boot) tells a reused pid
        # apart from the process the rule was made for.
        rule["start"] = start
    return rule


def parse_rules(raw):
    """Parse protected.json text; anything malformed yields an empty list."""
    try:
        data = json.loads(raw)
    except (ValueError, TypeError, RecursionError):
        # RecursionError: a few KB of nested brackets is enough to raise it.
        return []
    items = data.get("protected") if isinstance(data, dict) else None
    out = []
    for item in items if isinstance(items, list) else []:
        rule = normalize_rule(item)
        if rule and not any(r["kind"] == rule["kind"] and r["key"] == rule["key"] for r in out):
            out.append(rule)
        if len(out) >= MAX_RULES:
            break
    return out


def dump_rules(rules):
    return json.dumps({"version": 1, "protected": rules[:MAX_RULES]}, indent=2) + "\n"


def _ordered_names(rules):
    out = []
    for r in rules:
        for c in r.get("comms") or []:
            if ok_comm(c) and c not in out:
                out.append(c)
    return out


def earlyoom_names(rules):
    """This user's names for earlyoom, at most MAX_IGNORE_NAMES. The oldest
    entries win, so adding one never drops a name that already worked."""
    return sorted(_ordered_names(rules)[:MAX_IGNORE_NAMES])


def earlyoom_omitted(rules):
    """Names over the per-user limit, which earlyoom does not get."""
    return _ordered_names(rules)[MAX_IGNORE_NAMES:]


def admin_ignore(text):
    """True when an earlyoom environment text may pass its own --ignore.

    Fails closed instead of re-implementing systemd's environment-file parser:
    line continuations, backslash escapes and quotes are removed first, then
    any "--ignore" option anywhere counts, comments included. Only the
    separate option --ignore-root-user is told apart. A false positive only
    means OOM Guard adds nothing and the panel says the administrator's list
    is in charge; a false negative would override it."""
    squashed = re.sub(r"\\\r?\n", "", str(text or ""))
    squashed = squashed.replace("\\", "").replace('"', "").replace("'", "")
    return re.search(r"--ignore(?![-A-Za-z0-9_])", squashed) is not None



def regex_for_names(names):
    """The value earlyoom gets after --ignore: the desktop session plus the
    given names.

    Anchored on the whole comm. "." and "+" go in brackets so the regex needs
    no backslash (systemd unescapes those in EnvironmentFile values)."""
    names = sorted({n for n in names if ok_comm(n)} | set(SESSION_COMMS))
    return "^(" + "|".join(n.replace(".", "[.]").replace("+", "[+]") for n in names) + ")$"


def earlyoom_regex(rules):
    return regex_for_names(earlyoom_names(rules))


def names_in_regex(regex):
    """Inverse of regex_for_names, for checking what a running earlyoom has."""
    if not (isinstance(regex, str) and regex.startswith("^(") and regex.endswith(")$")):
        return set()
    return {n.replace("[.]", ".").replace("[+]", "+") for n in regex[2:-2].split("|") if n}
