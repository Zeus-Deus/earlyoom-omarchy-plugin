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
  assert.equal(Model.killerNotice(base).text, 'Protected from systemd-oomd and earlyoom');
  same(Model.killerNotice({oomd: {active: true, guardWatched: true}, earlyoom: {}}).level, 'warn');
  assert.match(Model.killerNotice({oomd: {}, earlyoom: {}}).text, /No OOM daemon/);
});

test('linkCommand quotes the plugin path for the terminal hand-off', () => {
  assert.equal(Model.linkCommand("/home/u/.config/omarchy/plugins/x/"),
               "sudo bash '/home/u/.config/omarchy/plugins/x/helper/install.sh'");
  assert.equal(Model.shellQuote("a'b"), "'a'\\''b'");
});

test('killRows labels each killer and only offers protect for unprotected apps', () => {
  const rows = Model.killRows([
    {by: 'systemd-oomd', name: 'A terminal', processes: 771, t: 1000},
    {by: 'earlyoom', name: 'chromium', signal: 'SIGTERM', rssBytes: 2 * 1024 ** 3, t: 1000, key: 'chromium'},
  ], 1000 + 3 * 3600, [{kind: 'app', key: 'chromium'}]);
  assert.equal(rows[0].sub, '3 h ago · systemd-oomd · 771 processes');
  assert.equal(rows[0].protectable, false);
  assert.equal(rows[1].sub, '3 h ago · earlyoom · 2.0 G · SIGTERM');
  assert.equal(rows[1].protected, true);
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
  same(detached, ['execDetached(["omarchy-launch-floating-terminal-with-presentation", Model.linkCommand(pluginDir)]);']);
});

test('no agent-instruction file ships at the repository root', () => {
  for (const f of ['AGENTS.md', 'CLAUDE.md', 'GEMINI.md']) assert.equal(fs.existsSync(path.join(root, f)), false, f);
});
