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

  visible: discordRunning
  implicitWidth: discordRunning ? iconImage.implicitWidth : 0
  implicitHeight: discordRunning ? iconImage.implicitHeight : 0

  Image {
    id: iconImage
    anchors.centerIn: parent
    source: "file://" + root._pluginDir + "icons/" + root.discordState + ".png"
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
      if (mouse.button === Qt.LeftButton) {
        root.bar.run("pkill -USR1 -f discord_bridge.py")
      } else if (mouse.button === Qt.RightButton) {
        root.bar.run("pkill -USR2 -f discord_bridge.py")
      }
    }
  }
}
