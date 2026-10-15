import QtQuick
import QtQuick.Controls as Controls
import Quickshell
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

// Bar button + one KeyboardPanel. Three tabs: Apps (open windows), Services
// (user services) and Kills (what systemd-oomd and earlyoom killed lately).
// Every row has one action: protect / unprotect. Processes live in Service.qml.
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

    readonly property var status: service.status
    readonly property var rows: tab === "apps" ? Model.appRows(status)
                               : (tab === "services" ? Model.serviceRows(status)
                               : Model.killRows(service.kills, Date.now() / 1000, status ? status.rules : []))
    readonly property var cursorRow: cursorActive && cursor >= 0 && cursor < rows.length ? rows[cursor] : null
    readonly property var killer: Model.killerNotice(status)
    readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
    readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
    readonly property color muted: bar && bar.muted ? bar.muted : Commons.Color.muted
    readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
    readonly property int pollMs: Math.max(2, Math.min(30, setting("refreshIntervalSec", 3))) * 1000

    implicitWidth: button.implicitWidth
    implicitHeight: button.implicitHeight

    function selectTab(name) {
        if (!name || name === tab) return;
        tab = name;
        cursor = 0;
        if (name === "kills") service.loadKills();
        if (panelFlick) panelFlick.contentY = 0;
    }
    function moveCursor(dy) {
        if (!cursorActive) { cursorActive = true; cursor = Math.max(0, Math.min(cursor, rows.length - 1)); return; }
        cursor = Model.clampIndex(cursor + dy, rows.length);
    }
    function activate(row) {
        if (!row || service.mutating) return;
        if (row.kind === "kill") {
            if (row.protectable) protectRow("app", row.key, row.name);
            return;
        }
        if (row.state === "foreign") { flash("Left alone: that service already has its own 50-oomguard.conf"); return; }
        if (row.protected) askUnprotect(row);
        else protectRow(row.kind, row.key, row.name);
    }
    function protectRow(kind, key, name) {
        errorText = "";
        service.protect(kind, key);
        flash(kind === "service" ? "Protected " + name + " · restart it to apply" : "Protecting " + name + "…");
    }
    function askUnprotect(row) {
        confirmKind = row.kind;
        confirmKey = row.key;
        confirmation.message = "Stop protecting " + Model.sanitize(row.name, 40) + "?\nUnder memory pressure it can be killed again.";
        confirmation.confirmText = "Unprotect";
        confirmation.selectedIndex = 0;
        confirmation.opened = true;
    }
    function confirmUnprotect() {
        service.unprotect(confirmKind, confirmKey);
        flash("Unprotected");
        confirmKind = "";
        confirmKey = "";
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
        else if (t === "L" && root.killer.action === "link") linkEarlyoom();
    }
    function linkEarlyoom() {
        root.close();
        service.linkEarlyoom();
    }

    readonly property Item panelFlick: panel.loadedContent ? panel.loadedContent.panelFlick : null
    function ensureVisible(item) {
        if (!item || !panelFlick) return;
        var pt = item.mapToItem(panelFlick.contentItem, 0, 0);
        var margin = Style.space(8);
        if (pt.y < panelFlick.contentY + margin) panelFlick.contentY = Math.max(0, pt.y - margin);
        else if (pt.y + item.height > panelFlick.contentY + panelFlick.height - margin)
            panelFlick.contentY = Math.min(Math.max(0, panelFlick.contentHeight - panelFlick.height), pt.y + item.height + margin - panelFlick.height);
    }

    onOpenedChanged: {
        if (opened) {
            cursorActive = false;
            errorText = "";
            service.refresh();
            if (tab === "kills") service.loadKills();
            Qt.callLater(function() { if (panel.loadedContent) panel.loadedContent.forceActiveFocus() });
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
                return;
            }
            if (op === "protect" || op === "unprotect" || op === "restart_service") {
                root.errorText = (result.errors && result.errors.length) ? Model.sanitize(result.errors[0].error, 160) : "";
                if (op === "protect" && result.kind === "app" && !(result.errors && result.errors.length))
                    root.flash("Protected " + Model.sanitize(result.name, 40));
                if (op === "restart_service") root.flash("Restarted " + Model.sanitize(result.key, 40));
                service.refresh();
                if (root.tab === "kills") service.loadKills();
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
    Timer { id: noticeTimer; interval: 3000; onTriggered: root.notice = "" }

    ShellIpc {
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
        function status(): string {
            var s = root.status;
            return JSON.stringify({
                opened: root.opened, tab: root.tab, cursor: root.cursorActive ? root.cursor : -1,
                rows: root.rows.map(function(r) { return {name: r.name, key: r.key, protected: r.protected, state: r.state || "", sub: r.sub}; }),
                notice: root.notice, error: root.errorText, killer: root.killer.text,
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
        focusTarget: panel.loadedContent
        contentWidth: panel.fittedContentWidth(Style.space(420))
        contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, Style.space(560))

        content: PanelKeyCatcher {
            id: keyCatcher
            property alias panelFlick: panelFlick
            implicitHeight: layout.implicitHeight
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
            Keys.onPressed: function(event) {
                if (confirmation.opened) { confirmation.handleKey(event); event.accepted = true; }
            }

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
                        text: "Link…"
                        bordered: true
                        foreground: root.foreground
                        fontFamily: root.fontFamily
                        fontSize: Style.font.bodySmall
                        tooltipText: "L · opens a terminal that runs helper/install.sh with sudo"
                        onClicked: root.linkEarlyoom()
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
                    WheelHandler {
                        acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad
                        onWheel: function(event) {
                            if (!panelFlick.interactive) return;
                            panelFlick.cancelFlick();
                            panelFlick.contentY = Model.wheelContentY(panelFlick.contentY, panelFlick.contentHeight, panelFlick.height,
                                                                      event.pixelDelta.y, event.angleDelta.y, Style.spacing.popupRowHeight * 3);
                            event.accepted = true;
                        }
                    }

                    Column {
                        id: list
                        width: panelFlick.width
                        spacing: Style.space(4)

                        Repeater {
                            model: root.rows.length
                            delegate: CursorSurface {
                                id: rowItem
                                required property int index
                                readonly property var entry: root.rows[index] || ({})
                                width: list.width
                                implicitHeight: Style.space(44)
                                hasCursor: root.cursorActive && root.cursor === index
                                current: entry.protected === true && entry.kind !== "kill"
                                foreground: root.foreground
                                onHasCursorChanged: if (hasCursor) root.ensureVisible(rowItem)

                                MouseArea {
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    onEntered: { root.cursorActive = true; root.cursor = rowItem.index }
                                    onClicked: root.activate(rowItem.entry)
                                }
                                Text {
                                    id: glyph
                                    anchors.left: parent.left
                                    anchors.leftMargin: Style.space(10)
                                    anchors.verticalCenter: parent.verticalCenter
                                    width: Style.space(22)
                                    textFormat: Text.PlainText
                                    text: rowItem.entry.kind === "kill" ? (rowItem.entry.protected ? "󰕥" : "󰚌")
                                          : (rowItem.entry.protected ? (rowItem.entry.state === "pending" ? "󰞀" : "󰕥") : "󰒙")
                                    color: rowItem.entry.kind === "kill" ? (rowItem.entry.protected ? Commons.Color.accent : root.urgent)
                                           : (rowItem.entry.protected ? Commons.Color.accent : root.muted)
                                    font.family: root.fontFamily
                                    font.pixelSize: Style.font.icon
                                }
                                Column {
                                    anchors.left: glyph.right
                                    anchors.right: trailing.left
                                    anchors.rightMargin: Style.space(8)
                                    anchors.verticalCenter: parent.verticalCenter
                                    spacing: Style.space(2)
                                    Text {
                                        width: parent.width
                                        textFormat: Text.PlainText
                                        elide: Text.ElideRight
                                        text: rowItem.entry.name || ""
                                        color: rowItem.entry.running === false ? root.muted : root.foreground
                                        font.family: root.fontFamily
                                        font.pixelSize: Style.font.body
                                        font.bold: rowItem.entry.protected === true && rowItem.entry.kind !== "kill"
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
                                    spacing: Style.space(10)
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
                                        visible: rowItem.entry.kind !== "kill" || rowItem.entry.protectable || rowItem.entry.protected
                                        checked: rowItem.entry.protected === true
                                        busy: service.mutating
                                        cursorRing: false
                                        foreground: root.foreground
                                        onToggled: root.activate(rowItem.entry)
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
                                text: root.tab === "kills" ? "󰄬" : "󰒙"
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
                                      : root.tab === "kills" ? (service.killsLoaded ? "Nothing was killed for lack of memory in the last 30 days." : "Reading the journal…")
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
                onCanceled: { opened = false; root.confirmKind = ""; root.confirmKey = ""; keyCatcher.forceActiveFocus() }
                onConfirmed: { opened = false; root.confirmUnprotect(); keyCatcher.forceActiveFocus() }
            }
        }
    }
}
