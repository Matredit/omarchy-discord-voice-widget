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
    try {
      url = decodeURIComponent(url)
    } catch (e) {}
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
      if (!discordRunning || !discordService) return
      if (mouse.button === Qt.LeftButton) {
        discordService.toggleMute()
      } else {
        discordService.toggleDeafen()
      }
    }
  }
}
