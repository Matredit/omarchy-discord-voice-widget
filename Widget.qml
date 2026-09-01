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

  readonly property var discordService: bar?.shell?.serviceFor("opoii.discord")
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
}
