import QtQuick
import Quickshell
import Quickshell.Hyprland
import Quickshell.Io
import "Model.js" as Model

// Process wiring only, no UI. Talks to bridge.py (one JSON request on stdin,
// one JSON response on stdout) and keeps protected apps out of
// systemd-oomd's reach as their windows open, whether or not the panel is.
Item {
    id: root
    readonly property string pythonBinary: "/usr/bin/python3"
    readonly property string pluginDir: decodeURIComponent(Qt.resolvedUrl(".").toString().replace(/^file:\/\//, "")).replace(/\/+$/, "")
    readonly property string bridgePath: pluginDir + "/bridge.py"

    property var status: null
    property var kills: []
    property bool killsLoaded: false
    property bool busy: false
    property var request: ({})
    property var queue: []
    property bool timedOut: false
    property int workerGeneration: 0
    // Status polls are not mutations; only real work dims the rows.
    readonly property bool mutating: busy && request.op !== "status" && request.op !== "kills" && request.op !== "apply"

    signal completed(string op, var result, var request)

    function run(payload) {
        if (busy) {
            // Collapse duplicate polls and auto-applies; writes always queue.
            if ((payload.op === "status" || payload.op === "apply" || payload.op === "kills")
                    && (request.op === payload.op || queue.some(function(q) { return q.op === payload.op })))
                return false;
            queue = queue.concat([payload]);
            return true;
        }
        request = payload;
        busy = true;
        timedOut = false;
        workerGeneration++;
        // restart_service waits on systemctl (bridge timeout 40 s).
        deadline.interval = payload.op === "restart_service" ? 50000 : 20000;
        worker.running = true;
        deadline.restart();
        return true;
    }
    function drainQueue() {
        if (busy || queue.length === 0) return;
        var next = queue[0];
        queue = queue.slice(1);
        run(next);
    }
    function finishWorker(code) {
        if (!busy) return;
        deadline.stop();
        var req = request;
        request = ({});
        busy = false;
        var result = Model.parseResponse(output.text, code, timedOut);
        if (result.ok && req.op === "status") status = result;
        if (result.ok && req.op === "kills") { kills = result.kills || []; killsLoaded = true; }
        completed(req.op, result, req);
        Qt.callLater(drainQueue);
    }

    function refresh() { run({op: "status"}) }
    function loadKills() { run({op: "kills", days: 30}) }
    function protect(kind, key) { run({op: "protect", kind: kind, key: key}) }
    function unprotect(kind, key) { run({op: "unprotect", kind: kind, key: key}) }
    function restartService(key) { run({op: "restart_service", key: key}) }
    function applyNow() { run({op: "apply"}) }

    // Hands one fixed command to Omarchy's floating terminal, where the user
    // reads it and types their own password. Nothing here runs as root and
    // no element of the command comes from the bridge or from a setting.
    function linkEarlyoom() {
        Quickshell.execDetached(["omarchy-launch-floating-terminal-with-presentation", Model.linkCommand(pluginDir)]);
    }

    Process {
        id: worker
        command: Model.boundedArgv([root.pythonBinary, "-B", root.bridgePath], Model.RESPONSE_CAP, 16384)
        stdinEnabled: true
        stdout: StdioCollector { id: output; waitForEnd: true }
        stderr: StdioCollector { waitForEnd: true }
        onStarted: {
            write(JSON.stringify(root.request));
            stdinEnabled = false;
            stdinEnabled = true;
        }
        onRunningChanged: {
            // FailedToStart emits runningChanged(false) but no exited signal.
            if (!running) {
                var generation = root.workerGeneration;
                Qt.callLater(function() {
                    if (generation === root.workerGeneration && !worker.running && root.busy)
                        root.finishWorker(-1);
                });
            }
        }
        onExited: function(code) { root.finishWorker(code) }
    }
    Timer {
        id: deadline
        interval: 20000
        onTriggered: {
            if (!root.busy) return;
            root.timedOut = true;
            if (worker.running) worker.signal(9);
            else root.finishWorker(-1);
        }
    }

    // A protected app's new window lands in app.slice like any other; move
    // it out shortly after it maps. Debounced so a burst of windows costs one
    // short bridge run. The same run remembers which app owns which scope,
    // so a later systemd-oomd kill line can be shown with the app's name.
    Connections {
        target: Hyprland
        function onRawEvent(event) {
            if (event && Model.isWindowEvent(String(event.name))) applyDebounce.restart();
        }
    }
    Timer {
        id: applyDebounce
        interval: 1200
        onTriggered: root.applyNow()
    }
    // Apps that were already open when the shell started (login, restart).
    Timer {
        interval: 4000
        running: true
        onTriggered: root.refresh()
    }
    onStatusChanged: {
        if (!status) return;
        var apps = status.apps || [];
        for (var i = 0; i < apps.length; i++) {
            if ((apps[i].exposed || []).length > 0 && Model.ruleFor(status.rules, "app", apps[i].key)) {
                applyDebounce.restart();
                return;
            }
        }
    }
}
