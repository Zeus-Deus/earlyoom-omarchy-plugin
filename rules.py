"""The protected list: one parser and one earlyoom regex builder.

Shared by bridge.py (runs as the desktop user inside the shell) and by
helper/earlyoom-sync (runs as root, installed by helper/install.sh). Keeping
both on this one file is what guarantees the panel's "applied" check and the
root side build the same string. Pure stdlib, no I/O beyond what callers pass.
"""
import json
import re

MAX_RULES = 64
MAX_COMMS = 4
MAX_IGNORE_NAMES = 32
# earlyoom matches /proc/<pid>/comm, which the kernel truncates to 15 bytes.
# The class is deliberately narrow: no whitespace, quotes, backslashes or
# regex syntax, so the generated value survives a systemd EnvironmentFile and
# an unbraced $VAR expansion as exactly one word.
COMM_RE = re.compile(r"^[A-Za-z0-9._+-]{1,15}$")
UNIT_RE = re.compile(r"^[A-Za-z0-9:_.\\@-]{1,200}\.service$")
CLASS_RE = re.compile(r"^[^\x00-\x1f\x7f/]{1,128}$")
# Interpreters, shells and launchers: ignoring one of these would protect
# every script on the machine, not the app the user picked.
GENERIC_COMMS = frozenset("""
bash sh zsh fish dash env sleep cat python python3 node nodejs deno bun java perl ruby
systemd systemd-run uwsm-app xdg-terminal-ex gtk-launch setsid sudo su timeout nohup
""".split())


def clean_text(value, limit=80):
    text = re.sub(r"[\x00-\x1f\x7f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]+", " ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def clean_comms(values):
    out = []
    for c in values or []:
        c = str(c or "")
        if COMM_RE.match(c) and c not in GENERIC_COMMS and c not in out:
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
        if not CLASS_RE.match(key):
            return None
    elif kind == "service":
        if not UNIT_RE.match(key):
            return None
    else:
        return None
    comms = item.get("comms")
    if comms is None and item.get("comm"):
        comms = [item.get("comm")]
    return {"kind": kind, "key": key, "name": clean_text(item.get("name") or key, 60),
            "comms": clean_comms(comms if isinstance(comms, list) else [])}


def parse_rules(raw):
    """Parse protected.json text; anything malformed yields an empty list."""
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
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


def earlyoom_names(rules):
    names = set()
    for r in rules:
        for c in r.get("comms") or []:
            if COMM_RE.match(c) and c not in GENERIC_COMMS:
                names.add(c)
    return sorted(names)[:MAX_IGNORE_NAMES]


def earlyoom_regex(rules):
    """The value earlyoom gets after --ignore, or "" for none.

    Anchored on the whole comm. "." and "+" go in brackets so the regex needs
    no backslash (systemd unescapes those in EnvironmentFile values)."""
    names = earlyoom_names(rules)
    if not names:
        return ""
    return "^(" + "|".join(n.replace(".", "[.]").replace("+", "[+]") for n in names) + ")$"
