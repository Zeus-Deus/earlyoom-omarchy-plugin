const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const Model = {};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '..', 'Model.js'), 'utf8'), Model);
const same = (a, b, m) => assert.deepEqual(JSON.parse(JSON.stringify(a)), b, m);
const root = path.join(__dirname, '..');

test('parseResponse trusts only a clean, well-formed reply', () => {
  same(Model.parseResponse('{"ok":true,"x":1}', 0, false), {ok: true, x: 1});
  assert.equal(Model.parseResponse('garbage', 0, false).ok, false);
  assert.match(Model.parseResponse('{"ok":true}', 0, true).error, /timed out/);
  assert.match(Model.parseResponse('{"ok":true}', 90, false).error, /too large/);
  assert.equal(Model.parseResponse('{"ok":false}', 0, false).error, 'The operation failed.');
  assert.equal(Model.parseResponse('', 127, false).ok, false);
});

test('sanitize removes controls, bidi overrides and line breaks', () => {
  const evil = 'Fire\u202efox\nInjected\u2028line\u0007\u200b';
  const out = Model.sanitize(evil, 200);
  assert.doesNotMatch(out, /[\u0000-\u001f\u202e\u2028\u200b]/);
  assert.equal(out, 'Fire fox Injected line');
});

test('appRows lists protected apps first, including ones that are not open', () => {
  const status = {
    rules: [{kind: 'app', key: 'obsidian', name: 'Obsidian'}, {kind: 'app', key: 'chromium', name: 'Chromium'}],
    apps: [
      {key: 'foot', name: 'Foot', windows: 2, memBytes: 50 << 20, exposed: ['a.scope']},
      {key: 'chromium', name: 'Chromium', windows: 1, memBytes: 900 << 20, exposed: [], guarded: true},
    ],
  };
  const rows = Model.appRows(status);
  same(rows.map(r => [r.key, r.protected, r.state]), [
    ['obsidian', true, 'idle'], ['chromium', true, 'guarded'], ['foot', false, 'open'],
  ]);
  assert.match(rows[0].sub, /Not open/);
  assert.equal(rows[2].sub, '2 windows');
});

test('an app with a scope still in app.slice shows as protecting, not protected', () => {
  const rows = Model.appRows({rules: [{kind: 'app', key: 'chromium', name: 'Chromium'}],
                              apps: [{key: 'chromium', name: 'Chromium', windows: 1, exposed: ['x.scope']}]});
  assert.equal(rows[0].state, 'pending');
});

test('serviceRows says when a restart is needed in either direction', () => {
  const rows = Model.serviceRows({
    rules: [{kind: 'service', key: 'a.service', name: 'a'}, {kind: 'service', key: 'gone.service', name: 'gone'}],
    services: [
      {key: 'a.service', name: 'a', guarded: false, memBytes: 10, dropin: 'ours'},
      {key: 'b.service', name: 'b', guarded: true, memBytes: 20, dropin: 'absent'},
      {key: 'c.service', name: 'c', guarded: false, memBytes: 30, dropin: 'foreign'},
    ],
  });
  const by = Object.fromEntries(rows.map(r => [r.key, r]));
  assert.match(by['a.service'].sub, /Restart to protect/);
  assert.match(by['b.service'].sub, /Restart to unprotect/);
  assert.equal(by['c.service'].state, 'foreign');
  assert.equal(by['gone.service'].running, false);
  assert.equal(rows[0].protected, true);
});

test('killerNotice warns when earlyoom runs without the link, and offers Link', () => {
  const base = {oomd: {active: true}, earlyoom: {active: true, linked: false, names: ['chromium']}, rules: []};
  same(Model.killerNotice(base), {text: 'earlyoom is running and does not know this list yet.', level: 'warn', action: 'link'});
  base.earlyoom = {active: true, linked: true, applied: true, names: ['chromium']};
  assert.match(Model.killerNotice(base).text, /can close any app/);
  base.rules = [{kind: 'app', key: 'chromium'}];
  assert.equal(Model.killerNotice(base).text, 'Switched-on apps are skipped by systemd-oomd and your earlyoom.');
  same(Model.killerNotice({oomd: {active: true, guardWatched: true}, earlyoom: {}}).level, 'warn');
  assert.match(Model.killerNotice({oomd: {}, earlyoom: {}}).text, /No OOM killer is running/);
});

test('linkCommand quotes the plugin path for the terminal hand-off', () => {
  assert.equal(Model.linkCommand("/home/u/.config/omarchy/plugins/x/"),
               "sudo bash '/home/u/.config/omarchy/plugins/x/helper/install.sh'");
  assert.equal(Model.shellQuote("a'b"), "'a'\\''b'");
});

test('killRows names who killed what; kills are history, not toggles', () => {
  const rows = Model.killRows([
    {by: 'systemd-oomd', name: 'Terminal · herdr', processes: 771, t: 1000},
    {by: 'earlyoom', name: 'chromium', signal: 'SIGTERM', rssBytes: 2 * 1024 ** 3, t: 1000, key: 'chromium'},
  ], 1000 + 3 * 3600, [{kind: 'app', key: 'chromium'}]);
  assert.equal(rows[0].sub, '3 h ago · Omarchy · 771 processes');
  assert.equal(rows[1].sub, '3 h ago · earlyoom · 2.0 G · SIGTERM');
  assert.equal(rows[0].protectable, false);
});

const terminals = {
  rules: [],
  apps: [{key: 'foot', name: 'Foot', memBytes: 6e9, windows: 2, exposed: ['a', 'b'], windowList: [
    {address: '0xaa', pid: 50, title: 'agents', workspace: 'workspace 4', running: 'herdr', memBytes: 5e9, shared: false, guarded: false},
    {address: '0xbb', pid: 60, title: 'notes', workspace: 'workspace 2', running: '', memBytes: 1e9, shared: false, guarded: false}]},
    {key: 'brave', name: 'Brave', memBytes: 1e9, windows: 1, exposed: ['c'], windowList: [
    {address: '0xcc', pid: 70, title: 'Inbox', workspace: 'workspace 3', running: '', memBytes: 1e9, shared: false, guarded: false}]}],
};

test('repeated kills of one thing fold into one row', () => {
  const now = 100000;
  const k = (t, name, by) => ({by: by || 'earlyoom', name, signal: 'SIGTERM', rssBytes: 5e8, t});
  const rows = Model.killRows([k(90000, 'quickshell'), k(89990, 'quickshell'), k(89980, 'quickshell'),
                               k(89970, 'chromium'), k(80000, 'quickshell')], now, []);
  same(rows.map(r => [r.name, r.count]), [['quickshell', 3], ['chromium', 1], ['quickshell', 1]]);
  assert.equal(rows[0].sub, '2 h ago · earlyoom · 3 times');
});

test('appRows lists each window under its app with workspace, program and title', () => {
  const rows = Model.appRows(terminals);
  same(rows.map(r => [r.kind, r.name]), [['app', 'Foot'], ['window', 'herdr'], ['window', 'notes'], ['app', 'Brave']]);
  assert.equal(rows[1].sub, 'workspace 4 · agents');
  assert.equal(rows[2].sub, 'workspace 2');
  assert.equal(rows[0].expandable, true);
  assert.equal(rows[3].expandable, false);  // one plain window: nothing to pick
  const folded = Model.appRows(terminals, {foot: false});
  same(folded.map(r => r.name), ['Foot', 'Brave']);
});

test('a protected window shows on its row and on its app', () => {
  const s = JSON.parse(JSON.stringify(terminals));
  s.rules = [{kind: 'window', key: '0xaa', name: 'Foot · herdr', comms: ['herdr'], pid: 50}];
  s.apps[0].windowList[0].guarded = true;
  const rows = Model.appRows(s, {foot: false});
  assert.equal(rows[0].sub, '1 of 2 windows protected');
  assert.equal(rows[0].state, 'partial');
  assert.equal(rows[1].protected, true);
  assert.equal(rows[1].sub, 'Protected · workspace 4 · agents');
  assert.equal(rows[2].protected, false);
});

test('a window that shares its process cannot be protected on its own', () => {
  const s = JSON.parse(JSON.stringify(terminals));
  s.apps[0].windowList[1].shared = true;
  const row = Model.appRows(s)[2];
  assert.equal(row.state, 'shared');
  assert.match(row.sub, /protect the app/);
});

test('killer cards show Omarchy oomd and your earlyoom side by side', () => {
  const now = 1792130000;
  const status = {
    oomd: {active: true, enabled: true, byOmarchy: true, swapLimit: 90, pressureLimit: 50},
    earlyoom: {installed: true, active: true, enabled: true, linked: false, applied: false,
               package: {version: '1.9.0-1', installedAt: 1784995596, explicit: true},
               limits: {memPercent: 10, swapPercent: 10, absolute: false}},
  };
  const kills = {days: 30, counts: {'systemd-oomd': 12, earlyoom: 6}, last: {'systemd-oomd': now - 3600, earlyoom: now - 60}, kills: []};
  const [o, e] = Model.killerCards(status, kills, now);
  assert.equal(o.badge, 'Omarchy');
  assert.equal(o.when, 'Swap over 90%, or memory stalled for 20 s');
  assert.equal(o.kills, '12 kills in 30 days · last 1 h ago');
  assert.equal(o.action, '');  // Omarchy owns it; the panel does not offer to stop it
  assert.equal(e.badge, 'yours');
  same([e.action, e.actionLabel, e.secondary], ['link', 'Link…', 'stop']);  // Enter does the safe thing
  assert.match(e.note, /^Your package 1\.9\.0-1 · since \d+ Jul · not linked to your list$/);
  status.earlyoom.linked = true; status.earlyoom.helperCurrent = false;
  same([Model.killerCards(status, kills, now)[1].actionLabel, Model.killerCards(status, kills, now)[1].note.split(' · ').pop()], ['Relink…', 'link out of date']);
  status.earlyoom.helperCurrent = true; status.earlyoom.applied = true;
  same([Model.killerCards(status, kills, now)[1].action, Model.killerCards(status, kills, now)[1].secondary], ['stop', '']);
  assert.equal(Model.killerCards(status, {days: 30, counts: {'systemd-oomd': 1}, last: {}}, now)[0].kills, '1 kill in 30 days');
  status.earlyoom.active = false;
  const off = Model.killerCards(status, kills, now)[1];
  same([off.action, off.secondary], ['start', 'remove']);
  const none = Model.killerCards({oomd: {}, earlyoom: {installed: false}}, null, now)[1];
  same([none.action, none.state, none.kills], ['install', 'Not installed', '']);
});

test('earlyoom commands come from one fixed table and unlink before removal', () => {
  assert.equal(Model.earlyoomCommand('stop', '/p'), 'sudo systemctl disable --now earlyoom.service');
  assert.equal(Model.earlyoomCommand('remove', '/p', false), 'omarchy pkg drop earlyoom');
  assert.equal(Model.earlyoomCommand('remove', "/p'x/", true), "sudo bash '/p'\\''x/helper/uninstall.sh' && omarchy pkg drop earlyoom");
  assert.equal(Model.earlyoomCommand('rm -rf /', '/p'), '');
  assert.equal(Model.earlyoomConfirm('start'), null);
  assert.match(Model.earlyoomConfirm('stop').text, /systemd-oomd keeps running/);
});

test('wheelContentY clamps and steps', () => {
  assert.equal(Model.wheelContentY(0, 500, 200, 0, -120, 84), 84);
  assert.equal(Model.wheelContentY(290, 500, 200, 0, -120, 84), 300);
  assert.equal(Model.wheelContentY(10, 500, 200, 0, 120, 84), 0);
  assert.equal(Model.wheelContentY(10, 500, 200, -5, 0, 84), 15);
});

test('every hint key in the footer is bound in Panel.qml', () => {
  const panel = fs.readFileSync(path.join(root, 'Panel.qml'), 'utf8');
  assert.match(panel, /t === "r" \|\| t === "R"/);
  assert.match(panel, /Model\.tabForKey\(t\)/);
  assert.match(panel, /t === "f" \|\| t === "F"/);
  // Space is PanelKeyCatcher's activate key; folding must not share it.
  assert.match(panel, /t === "w" \|\| t === "W"/);
  assert.doesNotMatch(panel, /t === " "/);
  assert.match(panel, /t === "o" \|\| t === "O"/);
  // h and l are cursor verbs in PanelKeyCatcher and never reach onTextKey.
  assert.doesNotMatch(panel, /t === "[hljkx]"/);
});

test('shipped QML has no TextInput-based controls and no bare Color.', () => {
  for (const f of ['Panel.qml', 'Service.qml']) {
    const src = fs.readFileSync(path.join(root, f), 'utf8');
    assert.doesNotMatch(src, /\b(TextField|NumberField|SearchableDropdown|MultiSelect|TextInput)\s*\{/, f);
    assert.doesNotMatch(src, /(^|[^.\w])Color\./m, f);
  }
});

test('every Process command goes through boundedArgv', () => {
  const src = fs.readFileSync(path.join(root, 'Service.qml'), 'utf8');
  const commands = src.match(/command:\s*[^\n]+/g) || [];
  assert.ok(commands.length > 0);
  for (const c of commands) assert.match(c, /Model\.boundedArgv\(/, c);
});

test('the bounded wrapper caps output and keeps the exit code', () => {
  const {execFileSync, spawnSync} = require('node:child_process');
  const argv = Model.boundedArgv(['bash', '-c', 'printf 0123456789'], 4, 0);
  const cut = spawnSync(argv[0], argv.slice(1));
  assert.equal(cut.status, 90);
  assert.equal(cut.stdout.toString(), '0123');
  const ok = Model.boundedArgv(['bash', '-c', 'printf ok; exit 3'], 64, 0);
  const r = spawnSync(ok[0], ok.slice(1));
  assert.equal(r.status, 3);
  assert.equal(r.stdout.toString(), 'ok');
  assert.equal(execFileSync(argv[0], ['-c', 'echo -n x']).toString(), 'x');
});

test('the only root path is a fixed command in a visible terminal', () => {
  const src = fs.readFileSync(path.join(root, 'Service.qml'), 'utf8') + fs.readFileSync(path.join(root, 'Panel.qml'), 'utf8');
  assert.doesNotMatch(src, /pkexec|"sudo"/);
  const detached = src.match(/execDetached\([^\n]+/g) || [];
  same(detached, ['execDetached(["omarchy-launch-floating-terminal-with-presentation", cmd]);']);
  assert.match(src, /var cmd = Model\.earlyoomCommand\(action, pluginDir, linked\);/);
});

test('no agent-instruction file ships at the repository root', () => {
  for (const f of ['AGENTS.md', 'CLAUDE.md', 'GEMINI.md']) assert.equal(fs.existsSync(path.join(root, f)), false, f);
});

test('window classes named like Object members still show up', () => {
  const apps = ['constructor', 'toString', '__proto__'].map(k => ({key: k, name: k, memBytes: 1, windows: 1, exposed: [], windowList: []}));
  const rows = Model.appRows({rules: [], apps}, {});
  same(rows.map(r => r.key), ['constructor', 'toString', '__proto__']);
});

test('a stopped earlyoom link is reported and offers Relink', () => {
  const status = {oomd: {}, earlyoom: {installed: true, active: true, linked: true, helperCurrent: true, syncWatching: false, applied: true}};
  assert.equal(Model.killerNotice(status).label, 'Relink…');
  assert.equal(Model.killerCards(status, null, 0)[1].actionLabel, 'Relink…');
});

test('kill counts at the read limit are shown as a lower bound', () => {
  const card = Model.killerCards({oomd: {}, earlyoom: {installed: true}}, {days: 30, counts: {earlyoom: 500}, capped: {earlyoom: true}, last: {}}, 0)[1];
  assert.match(card.kills, /^500\+ kills in 30 days/);
});

test('window rows carry the identity protect sends back', () => {
  const rows = Model.appRows(JSON.parse(JSON.stringify(terminals)).apps ? Object.assign({}, terminals, {apps: terminals.apps.map(a => Object.assign({}, a, {windowList: a.windowList.map(w => Object.assign({start: 7}, w))}))}) : terminals);
  const w = rows.find(r => r.kind === 'window');
  same([w.pid, w.start], [50, 7]);
});
