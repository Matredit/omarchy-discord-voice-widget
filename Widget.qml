import QtQuick
import Quickshell
import Quickshell.Io
import qs.Ui
import qs.Commons

BarWidget {
  id: root
  moduleName: "opoii.discord"

  property string discordState: "tray"
  property string iconsDir: Quickshell.env("HOME") + "/.config/omarchy/plugins/opoii.discord/icons/"

  implicitWidth: iconImage.implicitWidth
  implicitHeight: iconImage.implicitHeight

  Process {
    id: bridgeProcess
    command: ["python3", Quickshell.env("HOME") + "/.config/omarchy/plugins/opoii.discord/discord_bridge.py"]
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

  Image {
    id: iconImage
    anchors.centerIn: parent
    source: "file://" + root.iconsDir + root.discordState + ".png"
    width: Style.space(14)
    height: Style.space(14)
    fillMode: Image.PreserveAspectFit
  }
}
