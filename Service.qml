import QtQuick
import Quickshell
import Quickshell.Io

Item {
  id: root

  property string _pluginDir: {
    var url = Qt.resolvedUrl(".").toString().replace("file://", "")
    try {
      url = decodeURIComponent(url)
    } catch (e) {}
    return url.endsWith("/") ? url : url + "/"
  }

  property string discordState: "tray"
  property bool discordRunning: false

  function toggleMute() {
    if (bridgeProcess.running) {
      bridgeProcess.write("toggle_mute\n")
    }
  }

  function toggleDeafen() {
    if (bridgeProcess.running) {
      bridgeProcess.write("toggle_deafen\n")
    }
  }

  Component.onDestruction: {
    bridgeProcess.running = false
  }

  Process {
    id: bridgeProcess
    command: ["python3", root._pluginDir + "discord_bridge.py"]
    running: true
    stdinEnabled: true

    onExited: function(exitCode, exitStatus) {
      root.discordRunning = false
      root.discordState = "tray"
    }

    stdout: SplitParser {
      onRead: function(line) {
        var raw = String(line || "").trim()
        if (!raw) return
        try {
          var data = JSON.parse(raw)
          var validStates = ["tray", "tray-connected", "tray-muted", "tray-deafened", "tray-speaking"]
          if (data.state && validStates.indexOf(data.state) !== -1) {
            root.discordState = data.state
          }
          if (data.running !== undefined) {
            root.discordRunning = Boolean(data.running)
          }
        } catch (e) {
          console.warn("Discord bridge parse error:", e)
        }
      }
    }
  }
}
