import QtQuick
import Quickshell
import Quickshell.Io

Item {
  id: root

  property string _pluginDir: {
    var url = Qt.resolvedUrl(".").toString().replace("file://", "")
    return url.endsWith("/") ? url : url + "/"
  }

  property string discordState: "tray"

  Component.onDestruction: {
    bridgeProcess.running = false
  }

  Process {
    id: bridgeProcess
    command: ["python3", root._pluginDir + "discord_bridge.py"]
    running: true

    stdout: SplitParser {
      onRead: function(line) {
        var raw = String(line || "").trim()
        if (!raw) return
        try {
          var data = JSON.parse(raw)
          if (data.state) {
            root.discordState = data.state
          }
        } catch (e) {
          console.warn("Discord bridge parse error:", e)
        }
      }
    }
  }
}
