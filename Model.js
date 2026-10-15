// Pure helpers for OOM Guard. No Qt imports: tests/model.test.js runs this
// file in Node (vm context). QML only lays out what these functions return.

var RESPONSE_CAP = 1024 * 1024;
var TABS = ["apps", "services", "kills"];
var TAB_LABELS = {apps: "Apps", services: "Services", kills: "Kills"};

// Fixed-literal output cap for the bridge (see docs/DEVELOPMENT.md): the
// shell's StdioCollector would otherwise buffer whatever the child prints.
// Exit 90 = the response was larger than the cap and was cut off.
var BOUNDED_SCRIPT = 'o=$1 e=$2; shift 2; set -o pipefail; cap(){ head -c "$o"; [ "$(head -c 1 | wc -c)" -eq 0 ] || exit 90; }; if [ "$e" = 0 ]; then "$@" | cap; else { { "$@" | cap >&3; } 2>&1 | { head -c "$e" >&2; cat >/dev/null; }; } 3>&1; fi';

function boundedArgv(argv, outCap, errCap) {
    return ["bash", "-c", BOUNDED_SCRIPT, "oomguard-bounded", String(outCap), String(errCap)].concat(argv);
}

function parseResponse(text, code, timedOut) {
    if (timedOut) return {ok: false, error: "OOM Guard bridge timed out."};
    if (code === 90) return {ok: false, error: "Bridge response too large."};
    var raw = String(text || "");
    if (raw.length > RESPONSE_CAP) return {ok: false, error: "Bridge response too large."};
    var result = null;
    try { result = JSON.parse(raw); } catch (_) { result = null; }
    if (!result || typeof result !== "object" || typeof result.ok !== "boolean")
        return {ok: false, error: code === 0 ? "Bridge returned an unreadable response." : "Bridge could not run (exit " + code + ")."};
    if (!result.ok && typeof result.error !== "string") result.error = "The operation failed.";
    return result;
}

// Strip controls, bidi overrides and line breaks from anything that came
// from outside (window classes, unit names, journal text).
function sanitize(value, limit) {
    var s = String(value === undefined || value === null ? "" : value)
        .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]+/g, " ")
        .replace(/\s+/g, " ").trim();
    var max = limit || 120;
    return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

function formatBytes(n) {
    var v = Number(n) || 0;
    if (v < 1024 * 1024) return "0 M";
    if (v < 1024 * 1024 * 1024) return Math.round(v / (1024 * 1024)) + " M";
    var g = v / (1024 * 1024 * 1024);
    return (g < 10 ? g.toFixed(1) : String(Math.round(g))) + " G";
}

function ago(t, now) {
    var s = Math.max(0, Math.floor((Number(now) || 0) - (Number(t) || 0)));
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + " min ago";
    if (s < 86400) return Math.floor(s / 3600) + " h ago";
    var d = Math.floor(s / 86400);
    return d === 1 ? "yesterday" : d + " days ago";
}

function ruleFor(rules, kind, key) {
    var list = rules || [];
    for (var i = 0; i < list.length; i++) if (list[i].kind === kind && list[i].key === key) return list[i];
    return null;
}

// Apps tab: protected apps first (running or not), then other open windows.
function appRows(status) {
    var s = status || {};
    var apps = s.apps || [];
    var rules = s.rules || [];
    var rows = [];
    var seen = {};
    for (var i = 0; i < rules.length; i++) {
        var r = rules[i];
        if (r.kind !== "app") continue;
        var live = null;
        for (var j = 0; j < apps.length; j++) if (apps[j].key === r.key) { live = apps[j]; break; }
        seen[r.key] = true;
        var exposed = live ? (live.exposed || []).length : 0;
        rows.push({
            kind: "app", key: r.key, name: sanitize(live ? live.name : r.name, 48), protected: true, running: !!live,
            memBytes: live ? live.memBytes : 0,
            sub: !live ? "Not open · protected when it opens"
                : (exposed > 0 ? "Protecting…" : "Protected · " + windowsLabel(live.windows)),
            state: !live ? "idle" : (exposed > 0 ? "pending" : "guarded")
        });
    }
    for (var k = 0; k < apps.length; k++) {
        var a = apps[k];
        if (seen[a.key]) continue;
        rows.push({kind: "app", key: a.key, name: sanitize(a.name, 48), protected: false, running: true,
                   memBytes: a.memBytes, sub: windowsLabel(a.windows), state: "open"});
    }
    return rows;
}

function windowsLabel(n) {
    var c = Number(n) || 0;
    return c === 1 ? "1 window" : c + " windows";
}

// Services tab: user services oomd can kill, plus the ones already moved.
function serviceRows(status) {
    var s = status || {};
    var services = s.services || [];
    var rules = s.rules || [];
    var rows = [];
    for (var i = 0; i < services.length; i++) {
        var sv = services[i];
        var rule = ruleFor(rules, "service", sv.key);
        var protectedNow = !!sv.guarded;
        var sub;
        var state;
        if (rule && protectedNow) { sub = "Protected"; state = "guarded"; }
        else if (rule) { sub = "Restart to protect · r"; state = "pending"; }
        else if (protectedNow) { sub = "Restart to unprotect · r"; state = "pending"; }
        else { sub = "Can be killed by systemd-oomd"; state = "open"; }
        if (sv.dropin === "foreign") { sub = "Has its own 50-oomguard.conf · left alone"; state = "foreign"; }
        rows.push({kind: "service", key: sv.key, name: sanitize(sv.name, 48), protected: !!rule,
                   running: true, memBytes: sv.memBytes, sub: sub, state: state});
    }
    // Protected services that are not running right now.
    for (var j = 0; j < rules.length; j++) {
        var r = rules[j];
        if (r.kind !== "service") continue;
        var found = false;
        for (var k = 0; k < services.length; k++) if (services[k].key === r.key) { found = true; break; }
        if (!found) rows.unshift({kind: "service", key: r.key, name: sanitize(r.name, 48), protected: true,
                                  running: false, memBytes: 0, sub: "Not running · protected when it starts", state: "idle"});
    }
    rows.sort(function(a, b) {
        if (a.protected !== b.protected) return a.protected ? -1 : 1;
        return (b.memBytes || 0) - (a.memBytes || 0);
    });
    return rows;
}

function killRows(kills, now, rules) {
    var out = [];
    var list = kills || [];
    for (var i = 0; i < list.length; i++) {
        var k = list[i];
        var by = k.by === "earlyoom" ? "earlyoom" : "systemd-oomd";
        var detail = by === "earlyoom"
            ? (k.rssBytes ? formatBytes(k.rssBytes) + " · " : "") + sanitize(k.signal || "", 10)
            : (k.processes ? k.processes + " processes" : "whole app");
        var key = typeof k.key === "string" ? k.key : "";
        out.push({kind: "kill", key: key, name: sanitize(k.name, 40), by: by,
                  sub: ago(k.t, now) + " · " + by + " · " + detail,
                  protectable: key !== "" && !ruleFor(rules, "app", key),
                  protected: key !== "" && !!ruleFor(rules, "app", key)});
    }
    return out;
}

function protectedCount(status) {
    return status && status.rules ? status.rules.length : 0;
}

function heroMeta(status, error) {
    if (error) return sanitize(error, 80);
    if (!status) return "Reading memory…";
    var n = protectedCount(status);
    var mem = status.mem || {};
    var free = mem.total ? formatBytes(mem.available) + " free of " + formatBytes(mem.total) : "";
    var p = n === 0 ? "Nothing protected yet" : n + " protected";
    return free ? p + " · " + free : p;
}

// The one line under the hero that says who can kill what. Returns
// {text, level: "ok"|"warn", action: ""|"link"}.
function killerNotice(status) {
    if (!status) return {text: "", level: "ok", action: ""};
    var oomd = status.oomd || {};
    var eo = status.earlyoom || {};
    if (oomd.guardWatched)
        return {text: "systemd-oomd is set to watch oomguard.slice too, so protection does not hold.", level: "warn", action: ""};
    if (eo.active && !eo.linked && (eo.names || []).length > 0)
        return {text: "earlyoom is running and does not know this list yet.", level: "warn", action: "link"};
    if (eo.active && eo.linked && !eo.applied)
        return {text: "Updating earlyoom…", level: "ok", action: ""};
    var parts = [];
    if (oomd.active) parts.push("systemd-oomd");
    if (eo.active) parts.push("earlyoom");
    if (parts.length === 0) return {text: "No OOM daemon is running. Only the kernel can kill apps.", level: "ok", action: ""};
    return {text: "Protected from " + parts.join(" and "), level: "ok", action: ""};
}

function barGlyph(status) {
    if (!status) return "󰒙";
    var notice = killerNotice(status);
    if (notice.level === "warn") return "󰻌";
    return protectedCount(status) > 0 ? "󰕥" : "󰒙";
}

function tooltip(status) {
    if (!status) return "OOM Guard";
    var n = protectedCount(status);
    return "OOM Guard · " + (n === 0 ? "nothing protected" : n + " protected");
}

function hints(tab, row) {
    var parts = ["j/k move"];
    if (row) {
        if (tab === "kills") { if (row.protectable) parts.push("Enter protect"); }
        else parts.push(row.protected ? "Enter unprotect" : "Enter protect");
        if (tab === "services" && row.running) parts.push("r restart");
    }
    parts.push("Tab");
    parts.push("Esc");
    return parts.join("   ");
}

function nextTab(tab, delta) {
    var i = TABS.indexOf(tab);
    if (i < 0) i = 0;
    return TABS[(i + delta + TABS.length) % TABS.length];
}

function tabForKey(t) {
    if (t === "1") return "apps";
    if (t === "2") return "services";
    if (t === "3") return "kills";
    return "";
}

// POSIX single-quote, for the one command handed to Omarchy's terminal.
function shellQuote(s) {
    return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

function linkCommand(pluginDir) {
    return "sudo bash " + shellQuote(String(pluginDir).replace(/\/+$/, "") + "/helper/install.sh");
}

function clampIndex(i, n) {
    if (n <= 0) return -1;
    return Math.max(0, Math.min(n - 1, i));
}

function wheelContentY(contentY, contentHeight, height, pixelDeltaY, angleDeltaY, step) {
    var maxY = Math.max(0, contentHeight - height);
    var dy = pixelDeltaY !== 0 ? -pixelDeltaY : -(angleDeltaY / 120) * step;
    return Math.max(0, Math.min(maxY, contentY + dy));
}

// Hyprland events that may have created a window of a protected app.
function isWindowEvent(name) {
    return name === "openwindow" || name === "openwindowv2";
}

function hasAppRules(status) {
    var rules = status && status.rules ? status.rules : [];
    for (var i = 0; i < rules.length; i++) if (rules[i].kind === "app") return true;
    return false;
}
