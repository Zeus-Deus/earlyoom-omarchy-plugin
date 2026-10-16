// Pure helpers for OOM Guard. No Qt imports: tests/model.test.js runs this
// file in Node (vm context). QML only lays out what these functions return.

var RESPONSE_CAP = 1024 * 1024;
var TABS = ["apps", "services", "killers"];
var TAB_LABELS = {apps: "Apps", services: "Services", killers: "Killers"};

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

// Apps tab: one row per app, then one row per window when the app has
// several, or when its only window runs something worth naming (herdr in a
// terminal). Protected apps first, then by memory. Window rows carry what
// makes them recognisable: workspace, the program inside, title, memory.
function windowRule(rules, address) { return ruleFor(rules, "window", address); }

function appRows(status, expanded) {
    var s = status || {};
    var apps = s.apps || [];
    var rules = s.rules || [];
    var open = expanded || {};
    var rows = [];
    // Window classes are external strings: "constructor" or "__proto__" must
    // not hit Object.prototype.
    var seen = Object.create(null);
    var ordered = [];
    for (var i = 0; i < rules.length; i++) {
        var r = rules[i];
        if (r.kind !== "app") continue;
        var live = null;
        for (var j = 0; j < apps.length; j++) if (apps[j].key === r.key) { live = apps[j]; break; }
        seen[r.key] = true;
        ordered.push({app: live, rule: r});
    }
    for (var k = 0; k < apps.length; k++) if (!seen[apps[k].key]) ordered.push({app: apps[k], rule: null});
    // Window rules whose app row is not shown protected still need a row.
    for (var n = 0; n < ordered.length; n++) {
        var a = ordered[n].app;
        var rule = ordered[n].rule;
        var wins = a ? (a.windowList || []) : [];
        var winProtected = 0;
        for (var w = 0; w < wins.length; w++) if (windowRule(rules, wins[w].address)) winProtected++;
        var exposed = a ? (a.exposed || []).length : 0;
        var sub, state;
        if (rule && !a) { sub = "Not open · protected when it opens"; state = "idle"; }
        else if (rule) { sub = exposed > 0 ? "Protecting…" : "Protected · " + windowsLabel(a.windows); state = exposed > 0 ? "pending" : "guarded"; }
        else if (winProtected > 0) { sub = winProtected + " of " + windowsLabel(a.windows) + " protected"; state = "partial"; }
        else { sub = windowsLabel(a.windows); state = "open"; }
        var key = rule ? rule.key : a.key;
        var showWindows = !rule && wins.length > 0 && (wins.length > 1 || !!wins[0].running);
        var flag = Object.prototype.hasOwnProperty.call(open, key) ? open[key] : undefined;
        var isOpen = showWindows && (flag === true || winProtected > 0 || (flag !== false && wins.length <= 3));
        rows.push({kind: "app", key: key, name: sanitize(a ? a.name : rule.name, 48), protected: !!rule, running: !!a,
                   memBytes: a ? a.memBytes : 0, sub: sub, state: state,
                   expandable: showWindows, expanded: isOpen});
        if (!isOpen) continue;
        for (var v = 0; v < wins.length; v++) {
            var win = wins[v];
            var wr = windowRule(rules, win.address);
            var label = win.running ? sanitize(win.running, 24) : sanitize(win.title || "window", 40);
            var parts = [sanitize(win.workspace, 20)];
            if (win.running && win.title) parts.push(sanitize(win.title, 40));
            var guarded = !!wr && win.guarded;
            rows.push({kind: "window", key: win.address, app: key, name: label, protected: !!wr, running: true,
                       memBytes: win.memBytes, shared: !!win.shared, pid: win.pid, start: win.start,
                       sub: win.shared ? parts[0] + " · shares a process · protect the app"
                          : (wr ? (guarded ? "Protected · " : "Protecting… · ") : "") + parts.join(" · "),
                       state: win.shared ? "shared" : (wr ? (guarded ? "guarded" : "pending") : "open")});
        }
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

// Kill history, newest first. Back-to-back kills of the same thing by the
// same killer (earlyoom retrying a respawning process) fold into one row.
function killRows(kills, now, rules) {
    var out = [];
    var list = kills || [];
    for (var i = 0; i < list.length; i++) {
        var k = list[i];
        var by = k.by === "earlyoom" ? "earlyoom" : "systemd-oomd";
        var name = sanitize(k.name, 40);
        var prev = out.length ? out[out.length - 1] : null;
        if (prev && prev.by === by && prev.name === name && Math.abs(prev.t - Number(k.t)) <= 600) {
            prev.count++;
            prev.sub = prev.when + " · " + prev.who + " · " + prev.count + " times";
            continue;
        }
        var detail = by === "earlyoom"
            ? (k.rssBytes ? formatBytes(k.rssBytes) + " · " : "") + sanitize(k.signal || "", 10)
            : (k.processes ? k.processes + " processes" : "whole app");
        var who = by === "earlyoom" ? "earlyoom" : "Omarchy";
        out.push({kind: "kill", key: "", name: name, by: by, t: Number(k.t) || 0, count: 1,
                  when: ago(k.t, now), who: who,
                  sub: ago(k.t, now) + " · " + who + " · " + detail,
                  protectable: false, protected: false});
    }
    return out;
}

function percent(n) {
    var v = Number(n);
    return isFinite(v) ? (Math.round(v * 10) / 10) + "%" : "?";
}

function sinceDate(t) {
    if (!t) return "";
    var d = new Date(Number(t) * 1000);
    var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    return d.getDate() + " " + months[d.getMonth()];
}

// The two killer cards on the Killers tab. Each card: who it is, whether it
// runs, when it acts, what it kills, its kills in the window, and which
// action the panel offers for it.
function killsLine(n, days, last, now, capped) {
    var c = Number(n) || 0;
    var count = capped ? c + "+ kills" : (c === 1 ? "1 kill" : c + " kills");
    return count + " in " + days + " days" + (last ? " · last " + ago(last, now) : "");
}

function killerCards(status, killsResult, now) {
    var s = status || {};
    var o = s.oomd || {};
    var e = s.earlyoom || {};
    var counts = (killsResult && killsResult.counts) || {};
    var last = (killsResult && killsResult.last) || {};
    var capped = (killsResult && killsResult.capped) || {};
    var days = (killsResult && killsResult.days) || 30;
    var cards = [];
    var swap = o.swapLimit === null || o.swapLimit === undefined ? 90 : o.swapLimit;
    cards.push({
        id: "oomd", title: "systemd-oomd", badge: o.byOmarchy ? "Omarchy" : "systemd",
        state: o.active ? "Running" : (o.enabled ? "Stopped" : "Off"), active: !!o.active,
        when: "Swap over " + percent(swap) + ", or memory stalled for 20 s",
        what: "Closes a whole app · never Hyprland or the bar",
        kills: killsLine(counts["systemd-oomd"], days, last["systemd-oomd"], now, capped["systemd-oomd"]),
        note: o.byOmarchy ? "Turned on by Omarchy" : "",
        action: "", actionLabel: "", secondary: "", secondaryLabel: ""
    });
    var lim = e.limits || {memPercent: 10, swapPercent: 10};
    var stale = !!(e.linked && (e.helperCurrent === false || e.syncWatching === false));
    var needsLink = !!(e.installed && e.active && (!e.linked || stale));
    var state, action = "", actionLabel = "", secondary = "", secondaryLabel = "";
    if (!e.installed) { state = "Not installed"; action = "install"; actionLabel = "Install…"; }
    else if (e.active) {
        state = "Running";
        if (needsLink) { action = "link"; actionLabel = stale ? "Relink…" : "Link…"; secondary = "stop"; secondaryLabel = "Turn off…"; }
        else { action = "stop"; actionLabel = "Turn off…"; }
    } else {
        state = e.failed ? "Failed" : "Off";
        action = "start"; actionLabel = "Turn on…"; secondary = "remove"; secondaryLabel = "Remove…";
    }
    var note = [];
    if (e.package) note.push("Your package " + sanitize(e.package.version, 20) + " · since " + sinceDate(e.package.installedAt));
    if (e.installed && e.active && e.adminIgnore) note.push("uses its own --ignore");
    else if (e.installed && e.active && !e.linked) note.push("not linked to your list");
    else if (stale) note.push("link out of date");
    else if (e.linked && e.active) note.push(e.applied ? "follows your list" : "updating…");
    cards.push({
        id: "earlyoom", title: "earlyoom", badge: "yours", state: state, active: !!e.active,
        when: !e.installed ? "Not installed · Omarchy does not ship it"
              : (lim.absolute ? "Fixed memory and swap sizes"
              : "Free memory under " + percent(lim.memPercent) + " and free swap under " + percent(lim.swapPercent)),
        what: "Kills the biggest process · works on servers too",
        kills: e.installed ? killsLine(counts.earlyoom, days, last.earlyoom, now, capped.earlyoom) : "",
        note: note.join(" · "), action: action, actionLabel: actionLabel,
        secondary: secondary, secondaryLabel: secondaryLabel, linked: !!e.linked
    });
    return cards;
}

function killersRows(status, killsResult, now) {
    var rows = [];
    var cards = killerCards(status, killsResult, now);
    for (var i = 0; i < cards.length; i++) rows.push({kind: "killer", key: cards[i].id, card: cards[i], name: cards[i].title});
    var kills = killRows(killsResult ? killsResult.kills : [], now, status ? status.rules : []);
    for (var j = 0; j < kills.length; j++) rows.push(kills[j]);
    return rows;
}

// The only commands the Killers tab can run. Each goes to Omarchy's visible
// floating terminal, where the user reads it and types their own password.
// Nothing in them comes from the bridge, a setting or a window.
function earlyoomCommand(action, pluginDir, linked) {
    var unlink = "sudo bash " + shellQuote(String(pluginDir).replace(/\/+$/, "") + "/helper/uninstall.sh") + " && ";
    if (action === "start") return "sudo systemctl enable --now earlyoom.service";
    if (action === "stop") return "sudo systemctl disable --now earlyoom.service";
    if (action === "install") return "omarchy pkg add earlyoom && sudo systemctl enable --now earlyoom.service";
    if (action === "remove") return (linked ? unlink : "") + "omarchy pkg drop earlyoom";
    if (action === "link") return linkCommand(pluginDir);
    return "";
}

function earlyoomConfirm(action) {
    if (action === "stop") return {text: "Turn off earlyoom?\nOmarchy's systemd-oomd keeps running.", confirm: "Turn off"};
    if (action === "remove") return {text: "Remove the earlyoom package?\nOmarchy's systemd-oomd keeps running.", confirm: "Remove"};
    return null;
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
    if (eo.active && eo.linked && eo.helperCurrent === false)
        return {text: "earlyoom's link is from an older OOM Guard. Relink to update it.", level: "warn", action: "link", label: "Relink…"};
    if (eo.active && eo.linked && eo.syncFailed)
        return {text: "The earlyoom link failed its last update. Relink to repair it.", level: "warn", action: "link", label: "Relink…"};
    if (eo.active && eo.linked && eo.syncWatching === false)
        return {text: "The earlyoom link is not running, so list changes do not reach earlyoom.", level: "warn", action: "link", label: "Relink…"};
    if (eo.active && eo.adminIgnore)
        return {text: "earlyoom uses its own --ignore from /etc/default/earlyoom, so it does not use this list.", level: "warn", action: ""};
    if (eo.active && eo.linked && (eo.omitted || []).length > 0)
        return {text: "earlyoom takes 32 names per user; it skips " + sanitize((eo.omitted || []).join(", "), 60) + ".", level: "warn", action: ""};
    if (eo.active && eo.linked && !eo.applied)
        return {text: "Updating earlyoom…", level: "ok", action: ""};
    var parts = [];
    if (oomd.active) parts.push(oomd.byOmarchy ? "Omarchy's systemd-oomd" : "systemd-oomd");
    if (eo.active) parts.push("your earlyoom");
    if (parts.length === 0) return {text: "No OOM killer is running. Only the kernel can kill apps.", level: "ok", action: ""};
    var who = parts.join(" and ");
    if (protectedCount(status) === 0)
        return {text: who + " can close any app when memory runs out. Switch on the ones to keep.", level: "ok", action: ""};
    return {text: "Switched-on apps are skipped by " + who + ".", level: "ok", action: ""};
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
        if (row.kind === "window") { parts.push(row.shared ? "" : (row.protected ? "Enter unprotect" : "Enter protect")); parts.push("f show"); }
        else if (row.kind === "app" || row.kind === "service") parts.push(row.protected ? "Enter unprotect" : "Enter protect");
        else if (row.kind === "killer" && row.card) {
            if (row.card.actionLabel) parts.push("Enter " + row.card.actionLabel.replace("…", "").toLowerCase());
            if (row.card.secondaryLabel) parts.push("o " + row.card.secondaryLabel.replace("…", "").toLowerCase());
        }
        if (row.kind === "app" && row.expandable) parts.push("w windows");
        if (tab === "services" && row.running) parts.push("r restart");
    }
    parts.push("Tab");
    parts.push("Esc");
    return parts.filter(function(p) { return p !== ""; }).join("   ");
}

function nextTab(tab, delta) {
    var i = TABS.indexOf(tab);
    if (i < 0) i = 0;
    return TABS[(i + delta + TABS.length) % TABS.length];
}

function tabForKey(t) {
    if (t === "1") return "apps";
    if (t === "2") return "services";
    if (t === "3") return "killers";
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
    return name === "openwindow" || name === "openwindowv2" || name === "closewindow";
}

function hasAppRules(status) {
    var rules = status && status.rules ? status.rules : [];
    for (var i = 0; i < rules.length; i++) if (rules[i].kind === "app") return true;
    return false;
}
