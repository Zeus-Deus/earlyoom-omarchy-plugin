import QtQuick
import QtQuick.Controls as Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

// Bar button + one KeyboardPanel. Three tabs: Apps (apps and their single
// windows), Services (user services) and Killers (Omarchy's systemd-oomd and
// the user's earlyoom side by side, with what each killed). Processes live in
// Service.qml.
Panel {
    id: root
    moduleName: "io.github.zeus-deus.oomguard"
    ipcTarget: "io.github.zeus-deus.oomguard"
    manageIpc: false

    property string tab: "apps"
    property int cursor: 0
    property bool cursorActive: false
    property string notice: ""
    property string errorText: ""
    property string confirmKind: ""
    property string confirmKey: ""
    property string confirmAction: ""
    property var expanded: Object.create(null)

    readonly property var status: service.status
    readonly property var rows: tab === "apps" ? Model.appRows(status, expanded)
                               : (tab === "services" ? Model.serviceRows(status)
                               : Model.killersRows(status, service.killsResult, Date.now() / 1000))
    readonly property var cursorRow: cursorActive && cursor >= 0 && cursor < rows.length ? rows[cursor] : null
    readonly property var killer: Model.killerNotice(status)
    readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
    readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
    readonly property color muted: bar && bar.muted ? bar.muted : Commons.Color.muted
    readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
    // One wheel notch = three two-line rows, the same pace as the other
    // Omarchy plugin lists (PassPage, Drives).
    readonly property real wheelStep: (Style.spacing.rowPaddingX + Style.space(38)) * 3
    readonly property int pollMs: Math.max(2, Math.min(30, setting("refreshIntervalSec", 3))) * 1000

    implicitWidth: button.implicitWidth
    implicitHeight: button.implicitHeight

    function selectTab(name) {
        if (!name || name === tab) return;
        tab = name;
        cursor = 0;
        pointerGate.reset();
        if (name === "killers") service.loadKills();
        panelFlick.contentY = 0;
    }
    function moveCursor(dy) {
        pointerGate.reset();
        if (!cursorActive) { cursorActive = true; cursor = Math.max(0, Math.min(cursor, rows.length - 1)); return; }
        cursor = Model.clampIndex(cursor + dy, rows.length);
    }
    function activate(row) {
        if (!row || service.mutating) return;
        if (row.kind === "kill") return;
        if (row.kind === "killer") { killerAction(row.card, row.card.action); return; }
        if (row.state === "foreign") { flash("Left alone: that service already has its own 50-oomguard.conf"); return; }
        if (row.kind === "window" && row.shared) { flash("This window shares a process with others · protect the app"); return; }
        if (row.protected) askUnprotect(row);
        else protectRow(row.kind, row.key, row.name, row);
    }
    function protectRow(kind, key, name, row) {
        errorText = "";
        service.protect(kind, key, row ? row.pid : 0, row ? row.start : 0);
        flash(kind === "service" ? "Protected " + name + " · restart it to apply" : "Protecting " + name + "…");
    }
    function askUnprotect(row) {
        confirmAction = "";
        confirmKind = row.kind;
        confirmKey = row.key;
        confirmation.message = "Stop protecting " + Model.sanitize(row.name, 40) + "?\nUnder memory pressure it can be killed again.";
        confirmation.confirmText = "Unprotect";
        confirmation.selectedIndex = 0;
        confirmation.opened = true;
    }
    function confirmed() {
        if (confirmAction !== "") { runKiller(confirmAction); confirmAction = ""; return; }
        service.unprotect(confirmKind, confirmKey);
        flash("Unprotected");
        confirmKind = "";
        confirmKey = "";
    }
    // earlyoom actions open Omarchy's terminal with a fixed command. Turning
    // it off or removing it asks first, with Cancel selected.
    function killerAction(card, action) {
        if (!card || !action) return;
        var ask = Model.earlyoomConfirm(action);
        if (ask) {
            confirmAction = action;
            confirmation.message = ask.text;
            confirmation.confirmText = ask.confirm;
            confirmation.selectedIndex = 0;
            confirmation.opened = true;
            return;
        }
        runKiller(action);
    }
    function runKiller(action) {
        if (!status || !status.terminalAvailable) { errorText = "Omarchy's terminal launcher is missing"; return; }
        var linked = !!(status.earlyoom && status.earlyoom.linked);
        root.close();
        service.runEarlyoom(action, linked);
    }
    function showWindow(row) {
        if (!row || row.kind !== "window") return;
        root.close();
        service.focusWindow(row.key);
    }
    function toggleExpanded(row) {
        if (!row || row.kind !== "app" || !row.expandable) return;
        var next = Object.create(null);  // window classes are external strings
        for (var k in expanded) next[k] = expanded[k];
        next[row.key] = !row.expanded;
        expanded = next;
    }
    function restartCursorService() {
        var row = cursorRow;
        if (!row || row.kind !== "service" || !row.running || service.mutating) return;
        service.restartService(row.key);
        flash("Restarting " + row.name + "…");
    }
    function flash(text) { notice = text; noticeTimer.restart(); }
    function handleTextKey(t) {
        var tabName = Model.tabForKey(t);
        if (tabName !== "") { selectTab(tabName); return; }
        if (t === "r" || t === "R") restartCursorService();
        else if (t === "f" || t === "F") showWindow(cursorRow);
        else if (t === "w" || t === "W") toggleExpanded(cursorRow);
        else if ((t === "o" || t === "O") && cursorRow && cursorRow.kind === "killer") killerAction(cursorRow.card, cursorRow.card.secondary);
        else if (t === "L" && root.killer.action === "link") runKiller("link");
    }

    function ensureVisible(item) {
        if (!item) return;
        var pt = item.mapToItem(panelFlick.contentItem, 0, 0);
        var margin = Style.space(8);
        if (pt.y < panelFlick.contentY + margin) panelFlick.contentY = Math.max(0, pt.y - margin);
        else if (pt.y + item.height > panelFlick.contentY + panelFlick.height - margin)
            panelFlick.contentY = Math.min(Math.max(0, panelFlick.contentHeight - panelFlick.height), pt.y + item.height + margin - panelFlick.height);
    }

    onOpenedChanged: {
        if (opened) {
            cursorActive = false;
            pointerGate.reset();
            errorText = "";
            service.refresh();
            if (tab === "killers") service.loadKills();
            Qt.callLater(function() { keyCatcher.forceActiveFocus() });
        } else {
            confirmation.opened = false;
        }
    }
    onRowsChanged: if (cursor >= rows.length) cursor = Math.max(0, rows.length - 1)

    Service {
        id: service
        onCompleted: function(op, result, req) {
            if (!result.ok) {
                if (op !== "status" || !root.status) root.errorText = Model.sanitize(result.error, 160);
                // A failed change keeps its rule; show the real state again.
                if (op === "protect" || op === "unprotect") service.refresh();
                return;
            }
            if (op === "protect" || op === "unprotect" || op === "restart_service") {
                root.errorText = (result.errors && result.errors.length) ? Model.sanitize(result.errors[0].error, 160) : "";
                if (op === "protect" && result.kind !== "service" && !(result.errors && result.errors.length))
                    root.flash(result.warning ? Model.sanitize(result.warning, 120) : "Protected " + Model.sanitize(result.name, 40));
                if (op === "restart_service") root.flash("Restarted " + Model.sanitize(result.key, 40));
                service.refresh();
                if (root.tab === "killers") service.loadKills();
            } else if (op === "apply" && result.moved && result.moved.length) {
                service.refresh();
            }
        }
    }
    Timer {
        interval: root.pollMs
        repeat: true
        running: root.opened
        onTriggered: service.refresh()
    }
    PointerMoveGate { id: pointerGate; referenceItem: keyCatcher }
    Timer { id: noticeTimer; interval: 3000; onTriggered: root.notice = "" }

    IpcHandler {
        target: root.ipcTarget
        function open(): void { root.open() }
        function close(): void { root.close() }
        function show(): void { root.open() }
        function hide(): void { root.close() }
        function toggle(): void { root.toggle() }
        function tab(name: string): string { root.selectTab(name); return root.tab }
        function cursor(index: int): string { root.cursorActive = true; root.cursor = Model.clampIndex(index, root.rows.length); return String(root.cursor) }
        function activate(): string { root.activate(root.cursorRow); return "ok" }
        function protect(key: string): string { service.protect("app", key); return "ok" }
        function unprotect(key: string): string { service.unprotect("app", key); return "ok" }
        function key(t: string): string { root.handleTextKey(t); return "ok" }
        function status(): string {
            var s = root.status;
            return JSON.stringify({
                opened: root.opened, tab: root.tab, cursor: root.cursorActive ? root.cursor : -1,
                rows: root.rows.map(function(r) { return {kind: r.kind, name: r.name, key: r.key, protected: !!r.protected, state: r.state || "", sub: r.sub || "",
                                                          card: r.card || null}; }),
                notice: root.notice, error: root.errorText, killer: root.killer.text,
                scrollY: panelFlick.contentY, scrollMax: Math.max(0, panelFlick.contentHeight - panelFlick.height),
                earlyoom: s ? s.earlyoom : null, oomd: s ? s.oomd : null, confirm: confirmation.opened
            });
        }
    }

    BarIconButton {
        id: button
        anchors.fill: parent
        bar: root.bar
        text: Model.barGlyph(root.status)
        active: root.killer.level === "warn"
        tooltipText: Model.tooltip(root.status)
        onPressed: function(buttonCode) {
            if (buttonCode === Qt.MiddleButton) service.refresh();
            else root.toggle();
        }
    }

    KeyboardPanel {
        id: panel
        anchorItem: button
        owner: root
        bar: root.bar
        open: root.opened
        focusTarget: keyCatcher
        // Eager children (not the newer lazy `content:`) so the panel loads on
        // stable Omarchy 4.0.x as well as current dev builds.
        contentWidth: panel.fittedContentWidth(Style.space(420))
        contentHeight: panel.fittedContentHeight(layout.implicitHeight, Style.space(560))

        // The catcher is blocked while the dialog is open, so its keys bubble
        // up to here. Handling them on the catcher itself would let the same
        // Return that opens the dialog also answer it.
        Item {
            anchors.fill: parent
            Keys.onPressed: function(event) {
                if (confirmation.opened) { confirmation.handleKey(event); event.accepted = true; }
            }

            PanelKeyCatcher {
                id: keyCatcher
                anchors.fill: parent
                blocked: confirmation.opened
                onMoveRequested: function(dx, dy) {
                    if (dx !== 0) root.selectTab(Model.nextTab(root.tab, dx));
                    else root.moveCursor(dy);
                }
                onActivateRequested: if (root.cursorActive) root.activate(root.cursorRow)
                onCloseRequested: root.close()
                onTabRequested: function(direction) { root.selectTab(Model.nextTab(root.tab, direction)) }
                onTextKey: function(t) { root.handleTextKey(t) }

                Column {
                    id: layout
                    width: parent.width
                    spacing: Style.space(10)
                    enabled: !confirmation.opened

                    PanelHero {
                        id: hero
                        width: parent.width
                        title: "OOM Guard"
                        meta: Model.heroMeta(root.status, root.status ? "" : root.errorText)
                        foreground: root.foreground
                        fontFamily: root.fontFamily
                        iconComponent: Component {
                            Text {
                                textFormat: Text.PlainText
                                text: Model.barGlyph(root.status)
                                color: root.killer.level === "warn" ? root.urgent : root.foreground
                                font.family: root.fontFamily
                                font.pixelSize: Style.font.display
                            }
                        }
                    }

                    // Who can kill apps on this machine, in one line.
                    Row {
                        width: parent.width
                        spacing: Style.space(8)
                        visible: root.killer.text !== ""
                        Text {
                            id: killerText
                            width: parent.width - (linkButton.visible ? linkButton.width + parent.spacing : 0)
                            anchors.verticalCenter: parent.verticalCenter
                            textFormat: Text.PlainText
                            wrapMode: Text.WordWrap
                            text: root.killer.text
                            color: root.killer.level === "warn" ? root.urgent : root.muted
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption
                        }
                        Button {
                            id: linkButton
                            anchors.verticalCenter: parent.verticalCenter
                            visible: root.killer.action === "link" && root.status && root.status.terminalAvailable
                            text: root.killer.label || "Link…"
                            bordered: true
                            foreground: root.foreground
                            fontFamily: root.fontFamily
                            fontSize: Style.font.bodySmall
                            tooltipText: "L · opens a terminal that runs helper/install.sh with sudo"
                            onClicked: root.runKiller("link")
                        }
                    }

                    ButtonGroup {
                        id: tabs
                        width: parent.width
                        options: Model.TABS.map(function(t) { return {value: t, label: Model.TAB_LABELS[t]}; })
                        value: root.tab
                        focusable: false
                        foreground: root.foreground
                        fontFamily: root.fontFamily
                        fontSize: Style.font.bodySmall
                        onChanged: function(v) { root.selectTab(v) }
                    }

                    Flickable {
                        id: panelFlick
                        width: parent.width
                        height: Math.min(contentHeight, Style.space(380))
                        contentWidth: width
                        contentHeight: list.implicitHeight
                        clip: true
                        boundsBehavior: Flickable.StopAtBounds
                        flickableDirection: Flickable.VerticalFlick
                        interactive: contentHeight > height
                        Controls.ScrollBar.vertical: Controls.ScrollBar { policy: Controls.ScrollBar.AsNeeded }
                        // Flickable's own wheel handling starts a tiny kinetic flick per
                        // notch, which crawls. Step contentY directly; touchpads keep
                        // their own pixel deltas.
                        WheelHandler {
                            acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad
                            onWheel: function(event) {
                                if (!panelFlick.interactive) return;
                                panelFlick.cancelFlick();
                                panelFlick.contentY = Model.wheelContentY(panelFlick.contentY, panelFlick.contentHeight, panelFlick.height,
                                                                          event.pixelDelta.y, event.angleDelta.y, root.wheelStep);
                                event.accepted = true;
                            }
                        }

                        Column {
                            id: list
                            width: panelFlick.width
                            spacing: Style.space(4)

                            Repeater {
                                model: root.rows.length
                                delegate: Item {
                                    id: slot
                                    required property int index
                                    readonly property var entry: root.rows[index] || ({})
                                    readonly property bool isCard: entry.kind === "killer"
                                    width: list.width
                                    implicitHeight: isCard ? card.implicitHeight : rowItem.implicitHeight

                                    KillerCard {
                                        id: card
                                        visible: slot.isCard
                                        width: parent.width
                                        rowIndex: slot.index
                                        data_: slot.isCard ? slot.entry.card : ({})
                                    }

                                    CursorSurface {
                                        id: rowItem
                                        visible: !slot.isCard
                                        width: parent.width
                                        readonly property var entry: slot.entry
                                        readonly property bool child: entry.kind === "window"
                                        implicitHeight: Style.space(entry.kind === "kill" ? 40 : 44)
                                        hasCursor: root.cursorActive && root.cursor === slot.index
                                        current: entry.protected === true
                                        foreground: root.foreground
                                        onHasCursorChanged: if (hasCursor) root.ensureVisible(slot)

                                        MouseArea {
                                            anchors.fill: parent
                                            hoverEnabled: true
                                            acceptedButtons: Qt.LeftButton | Qt.MiddleButton
                                            // Only real pointer movement moves the cursor. A row sliding
                                            // under a resting pointer while the wheel scrolls must not
                                            // grab it, or ensureVisible pulls the list back.
                                            onPositionChanged: function(mouse) {
                                                if (pointerGate.moved(rowItem, mouse)) { root.cursorActive = true; root.cursor = slot.index }
                                            }
                                            onClicked: function(mouse) {
                                                if (mouse.button === Qt.MiddleButton) root.showWindow(rowItem.entry);
                                                else if (rowItem.entry.kind === "app" && rowItem.entry.expandable) root.toggleExpanded(rowItem.entry);
                                                else root.activate(rowItem.entry);
                                            }
                                        }
                                        Text {
                                            id: glyph
                                            anchors.left: parent.left
                                            anchors.leftMargin: Style.space(rowItem.child ? 30 : 10)
                                            anchors.verticalCenter: parent.verticalCenter
                                            width: Style.space(22)
                                            textFormat: Text.PlainText
                                            text: rowItem.entry.kind === "kill" ? "󰚌"
                                                  : rowItem.entry.kind === "window" ? (rowItem.entry.protected ? "󰕥" : "󰆍")
                                                  : (rowItem.entry.protected ? (rowItem.entry.state === "pending" ? "󰞀" : "󰕥")
                                                     : (rowItem.entry.state === "partial" ? "󰞀" : "󰒙"))
                                            color: rowItem.entry.kind === "kill" ? (rowItem.entry.by === "earlyoom" ? root.urgent : root.muted)
                                                   : (rowItem.entry.protected || rowItem.entry.state === "partial" ? Commons.Color.accent : root.muted)
                                            font.family: root.fontFamily
                                            font.pixelSize: Style.font.icon
                                        }
                                        Column {
                                            anchors.left: glyph.right
                                            anchors.right: trailing.left
                                            anchors.rightMargin: Style.space(8)
                                            anchors.verticalCenter: parent.verticalCenter
                                            spacing: Style.space(2)
                                            Row {
                                                width: parent.width
                                                spacing: Style.space(6)
                                                Text {
                                                    width: Math.min(implicitWidth, parent.width - (chevron.visible ? chevron.width + parent.spacing : 0))
                                                    textFormat: Text.PlainText
                                                    elide: Text.ElideRight
                                                    text: rowItem.entry.name || ""
                                                    color: rowItem.entry.running === false ? root.muted : root.foreground
                                                    font.family: root.fontFamily
                                                    font.pixelSize: Style.font.body
                                                    font.bold: rowItem.entry.protected === true
                                                }
                                                Text {
                                                    id: chevron
                                                    visible: rowItem.entry.expandable === true
                                                    anchors.verticalCenter: parent.verticalCenter
                                                    textFormat: Text.PlainText
                                                    text: rowItem.entry.expanded ? "󰅀" : "󰅂"
                                                    color: root.muted
                                                    font.family: root.fontFamily
                                                    font.pixelSize: Style.font.caption
                                                }
                                            }
                                            Text {
                                                width: parent.width
                                                textFormat: Text.PlainText
                                                elide: Text.ElideRight
                                                text: rowItem.entry.sub || ""
                                                color: rowItem.entry.state === "pending" || rowItem.entry.state === "foreign" ? root.urgent : root.muted
                                                font.family: root.fontFamily
                                                font.pixelSize: Style.font.caption
                                            }
                                        }
                                        Row {
                                            id: trailing
                                            anchors.right: parent.right
                                            anchors.rightMargin: Style.space(10)
                                            anchors.verticalCenter: parent.verticalCenter
                                            spacing: Style.space(8)
                                            PanelActionButton {
                                                anchors.verticalCenter: parent.verticalCenter
                                                visible: rowItem.entry.kind === "window"
                                                opacity: rowItem.hasCursor ? 1 : 0.35
                                                iconText: "󰈈"
                                                foreground: root.foreground
                                                tooltipText: "f · show this window"
                                                onClicked: root.showWindow(rowItem.entry)
                                            }
                                            Text {
                                                anchors.verticalCenter: parent.verticalCenter
                                                visible: rowItem.entry.kind !== "kill" && (rowItem.entry.memBytes || 0) > 0
                                                textFormat: Text.PlainText
                                                text: Model.formatBytes(rowItem.entry.memBytes)
                                                color: root.muted
                                                font.family: root.fontFamily
                                                font.pixelSize: Style.font.caption
                                            }
                                            ToggleSwitch {
                                                anchors.verticalCenter: parent.verticalCenter
                                                visible: rowItem.entry.kind !== "kill"
                                                enabled: !(rowItem.entry.kind === "window" && rowItem.entry.shared)
                                                opacity: enabled ? 1 : 0.35
                                                checked: rowItem.entry.protected === true
                                                busy: service.mutating
                                                cursorRing: false
                                                foreground: root.foreground
                                                onToggled: root.activate(rowItem.entry)
                                            }
                                        }
                                    }
                                }
                            }

                            Column {
                                width: list.width
                                visible: root.rows.length === 0
                                topPadding: Style.space(28)
                                bottomPadding: Style.space(28)
                                spacing: Style.space(6)
                                Text {
                                    anchors.horizontalCenter: parent.horizontalCenter
                                    textFormat: Text.PlainText
                                    text: "󰒙"
                                    color: root.muted
                                    font.family: root.fontFamily
                                    font.pixelSize: Style.space(30)
                                }
                                Text {
                                    width: parent.width
                                    horizontalAlignment: Text.AlignHCenter
                                    wrapMode: Text.WordWrap
                                    textFormat: Text.PlainText
                                    text: !root.status ? "Reading…"
                                          : root.tab === "apps" ? "No open windows." : "No user services in app.slice."
                                    color: root.muted
                                    font.family: root.fontFamily
                                    font.pixelSize: Style.font.body
                                }
                            }
                        }
                    }

                    Item {
                        id: footer
                        width: parent.width
                        height: Style.space(24)
                        Text {
                            anchors.left: parent.left
                            anchors.right: hintsText.left
                            anchors.rightMargin: Style.space(10)
                            anchors.verticalCenter: parent.verticalCenter
                            textFormat: Text.PlainText
                            elide: Text.ElideRight
                            text: root.errorText !== "" ? root.errorText : root.notice
                            color: root.errorText !== "" ? root.urgent : root.muted
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption
                        }
                        Text {
                            id: hintsText
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            textFormat: Text.PlainText
                            text: Model.hints(root.tab, root.cursorRow)
                            color: root.muted
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption
                        }
                    }
                }

                // Takes the hover so a row's tooltip never draws over the dialog.
                MouseArea {
                    anchors.fill: parent
                    visible: confirmation.opened
                    hoverEnabled: true
                    acceptedButtons: Qt.NoButton
                }
                ConfirmDialog {
                    id: confirmation
                    anchors.fill: parent
                    z: 10
                    selectedIndex: 0
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onCanceled: { opened = false; root.confirmKind = ""; root.confirmKey = ""; root.confirmAction = ""; keyCatcher.forceActiveFocus() }
                    onConfirmed: { opened = false; root.confirmed(); keyCatcher.forceActiveFocus() }
                }
            }
        }
    }

    // One OOM killer: name + who owns it, state, when it acts, what it kills,
    // its recent kill count, and the one or two actions the panel offers.
    component KillerCard: CursorSurface {
        id: kc
        property int rowIndex: 0
        property var data_: ({})
        bordered: true
        hasCursor: root.cursorActive && root.cursor === rowIndex
        foreground: root.foreground
        implicitHeight: kcCol.implicitHeight + Style.space(20)
        onHasCursorChanged: if (hasCursor) root.ensureVisible(kc)
        MouseArea {
            anchors.fill: parent
            hoverEnabled: true
            acceptedButtons: Qt.NoButton
            onPositionChanged: function(mouse) {
                if (pointerGate.moved(kc, mouse)) { root.cursorActive = true; root.cursor = kc.rowIndex }
            }
        }
        Column {
            id: kcCol
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Style.space(12)
            anchors.rightMargin: Style.space(12)
            spacing: Style.space(3)
            Item {
                width: parent.width
                implicitHeight: Math.max(kcTitle.implicitHeight, kcButtons.implicitHeight)
                Row {
                    id: kcTitle
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(8)
                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        textFormat: Text.PlainText
                        text: "●"
                        color: kc.data_.active ? Commons.Color.accent : root.muted
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                    }
                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        textFormat: Text.PlainText
                        text: kc.data_.title || ""
                        color: root.foreground
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.body
                        font.bold: true
                    }
                    Rectangle {
                        anchors.verticalCenter: parent.verticalCenter
                        radius: Style.cornerRadius
                        color: "transparent"
                        border.width: 1
                        border.color: root.muted
                        implicitWidth: kcBadge.implicitWidth + Style.space(10)
                        implicitHeight: kcBadge.implicitHeight + Style.space(2)
                        Text {
                            id: kcBadge
                            anchors.centerIn: parent
                            textFormat: Text.PlainText
                            text: kc.data_.badge || ""
                            color: root.muted
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption
                        }
                    }
                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        textFormat: Text.PlainText
                        text: kc.data_.state || ""
                        color: kc.data_.active ? root.foreground : root.muted
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                    }
                }
                Row {
                    id: kcButtons
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(6)
                    Button {
                        visible: (kc.data_.secondary || "") !== ""
                        text: kc.data_.secondaryLabel || ""
                        bordered: true
                        foreground: root.foreground
                        fontFamily: root.fontFamily
                        fontSize: Style.font.caption
                        onClicked: root.killerAction(kc.data_, kc.data_.secondary)
                    }
                    Button {
                        visible: (kc.data_.action || "") !== ""
                        text: kc.data_.actionLabel || ""
                        bordered: true
                        foreground: root.foreground
                        fontFamily: root.fontFamily
                        fontSize: Style.font.caption
                        onClicked: root.killerAction(kc.data_, kc.data_.action)
                    }
                }
            }
            Repeater {
                model: [kc.data_.when, kc.data_.what, kc.data_.kills, kc.data_.note]
                delegate: Text {
                    required property var modelData
                    visible: !!modelData
                    width: kcCol.width
                    textFormat: Text.PlainText
                    wrapMode: Text.WordWrap
                    text: modelData || ""
                    color: root.muted
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                }
            }
        }
    }
}
