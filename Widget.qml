import QtQuick
import Quickshell
import Quickshell.Io
import qs.Ui
import qs.Commons

BarWidget {
  id: root
  moduleName: "opoii.discord"

  property string _pluginDir: {
    var url = Qt.resolvedUrl(".").toString().replace("file://", "")
    return url.endsWith("/") ? url : url + "/"
  }

  readonly property var discordService: bar?.shell?.ensureService("opoii.discord")
  property string discordState: discordService ? discordService.discordState : "tray"
  property bool discordRunning: discordService ? discordService.discordRunning : false
  property bool inVoiceChannel: discordState !== "tray" && discordRunning

  visible: inVoiceChannel
  implicitWidth: inVoiceChannel ? iconImage.implicitWidth : 0
  implicitHeight: inVoiceChannel ? iconImage.implicitHeight : 0

  Image {
    id: iconImage
    anchors.centerIn: parent
    source: inVoiceChannel ? "file://" + root._pluginDir + "icons/" + root.discordState + ".png" : ""
    width: Style.space(14)
    height: Style.space(14)
    fillMode: Image.PreserveAspectFit
  }

  MouseArea {
    anchors.fill: parent
    acceptedButtons: Qt.LeftButton | Qt.RightButton
    cursorShape: Qt.PointingHandCursor
    onClicked: function(mouse) {
      if (!discordRunning) return
      var runtimeDir = Quickshell.env("XDG_RUNTIME_DIR") || ("/tmp/opoii_discord_" + Quickshell.env("UID"))
      var pidFile = runtimeDir + "/discord_bridge.pid"
      var cmd = mouse.button === Qt.LeftButton ? "kill -USR1 $(cat " + pidFile + " 2>/dev/null)" : "kill -USR2 $(cat " + pidFile + " 2>/dev/null)"
      root.bar.run(cmd)
    }
  }
}
