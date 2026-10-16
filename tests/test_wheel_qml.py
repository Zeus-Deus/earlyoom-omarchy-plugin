"""Run the panel's real WheelHandler and wheel step in Qt, without a desktop.

One mouse notch must move three two-line rows at once (the same pace as the
PassPage and Drives lists), high-resolution wheels must add up to the same
distance, an existing kinetic flick must stop, and both ends must clamp.
"""
import os
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER = "/usr/lib/qt6/bin/qmltestrunner"


def qml_block(source, marker):
    start = source.index(marker)
    pos = source.index("{", start)
    depth, end = 1, pos + 1
    while depth:
        depth += {"{": 1, "}": -1}.get(source[end], 0)
        end += 1
    return source[start:end]


@pytest.mark.skipif(not os.path.exists(RUNNER), reason="Qt6 Quick Test runner required")
def test_actual_panel_wheel_handler(tmp_path):
    panel = (ROOT / "Panel.qml").read_text()
    handler = qml_block(panel, "WheelHandler {")
    step = re.search(r"^\s*readonly property (?:real|int) wheelStep: ([^\n]+)", panel, re.M)
    assert step, "Panel.qml must define wheelStep"
    # Import the implementation itself, never a second copy of its arithmetic.
    shutil.copyfile(ROOT / "Model.js", tmp_path / "Model.js")
    qml = """import QtQuick
import QtTest
import "Model.js" as Model

Item {
    id: root
    width: 400; height: 400
    property real wheelStep: %s
    QtObject {
        id: style
        property QtObject spacing: QtObject {
            property real popupRowHeight: 28
            property real rowPaddingX: 12
        }
        function space(px) { return px; }
    }
    Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width; contentHeight: 6000
        interactive: contentHeight > height
        boundsBehavior: Flickable.StopAtBounds
        %s
        Rectangle { width: 400; height: 6000; color: "grey" }
    }
    TestCase {
        name: "OomGuardWheel"
        when: windowShown
        function init() { panelFlick.cancelFlick(); panelFlick.contentY = 1000; wait(30); }
        function test_one_notch_moves_three_rows_at_once() {
            mouseWheel(panelFlick, 200, 200, 0, -120);
            compare(panelFlick.contentY, 1150);
            wait(400);
            compare(panelFlick.contentY, 1150);
        }
        function test_fast_notches_add_up() {
            for (var i = 0; i < 5; i++) { mouseWheel(panelFlick, 200, 200, 0, -120); wait(20); }
            wait(400);
            compare(panelFlick.contentY, 1750);
        }
        function test_high_resolution_wheel() {
            for (var i = 0; i < 8; i++) mouseWheel(panelFlick, 200, 200, 0, -15);
            wait(400);
            compare(panelFlick.contentY, 1150);
        }
        function test_wheel_stops_an_existing_flick() {
            panelFlick.flick(0, -1500);
            wait(30);
            verify(panelFlick.flicking, "fixture must have a kinetic flick in flight");
            mouseWheel(panelFlick, 200, 200, 0, -120);
            verify(!panelFlick.flicking, "wheel must cancel kinetic motion before stepping");
            var at = panelFlick.contentY;
            wait(400);
            compare(panelFlick.contentY, at);
        }
        function test_clamps_to_both_ends() {
            panelFlick.contentY = 0;
            mouseWheel(panelFlick, 200, 200, 0, 120);
            wait(100); compare(panelFlick.contentY, 0);
            panelFlick.contentY = panelFlick.contentHeight - panelFlick.height;
            mouseWheel(panelFlick, 200, 200, 0, -120);
            wait(100); compare(panelFlick.contentY, panelFlick.contentHeight - panelFlick.height);
        }
    }
}
""" % (step.group(1), handler)
    # Only the theme object is substituted; the production handler is unedited.
    qml = qml.replace("Style.", "style.")
    f = tmp_path / "tst_oomguard_wheel.qml"
    f.write_text(qml)
    result = subprocess.run(
        [RUNNER, "-input", str(f)], capture_output=True, text=True, timeout=60,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen", "QT_QUICK_BACKEND": "software"},
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_rows_follow_real_pointer_movement_only():
    panel = (ROOT / "Panel.qml").read_text()
    # A row sliding under a resting pointer during a wheel scroll must not
    # take the cursor (and pull the list back through ensureVisible).
    assert "onEntered" not in panel
    assert panel.count("pointerGate.moved(") == 2
    assert "PointerMoveGate { id: pointerGate" in panel
