import QtQuick
import Quickshell
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
  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    iconComponent: Component {
      Image {
        anchors.centerIn: parent
        source: root.inVoiceChannel ? "file://" + root._pluginDir + "icons/" + root.discordState + ".png" : ""
        width: Style.bar.iconCanvas
        height: Style.bar.iconCanvas
        fillMode: Image.PreserveAspectFit
        smooth: true
      }
    }
    tooltipText: root.inVoiceChannel ? root.discordState : ""
    onPressed: function(b) {
      if (!root.discordRunning || !root.discordService) return
      if (b === Qt.RightButton) root.discordService.toggleDeafen()
      else if (b === Qt.LeftButton) root.discordService.toggleMute()
    }
  }
}
