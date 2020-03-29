# -*- coding: utf-8 -*-
import os

from PyQt5 import uic, QtCore
from PyQt5.QtWidgets import *

from ui.analysiscontrol import AnalysisControl
from ui.configcontrol import ConfigControl


class ToolBarControl(QMainWindow):
    resized = QtCore.pyqtSignal()
    root_path = os.path.dirname(os.path.abspath(__file__)).replace('ui', '')

    def __init__(self):
        super(ToolBarControl, self).__init__()

        self.configControl = ConfigControl(self, self.root_path)
        self.analysisControl = AnalysisControl(self, self.root_path)

        self.set_configMenu()

    def toolbar_clicked(self, toolbar):
        toolbarList = ['analysisMenu', 'configMenu']
        getattr(self, 'set_%s' % toolbarList[toolbarList.index(toolbar.objectName())])()

    def set_analysisMenu(self):
        self.toolBar.close()
        uic.loadUi(self.root_path + 'ui/analysiscontrol.ui', self)

        # Connect ToolBar
        tb = self.toolBar
        tb.actionTriggered[QAction].connect(self.toolbar_clicked)

        # Print Options
        self.analysisControl.print_information(self.configControl.target_options)

        # Connect Button & Layouts
        self.analysisControl.connect_layouts()

        # Connect Button & Layouts
        try:
            self.resized.disconnect(self.ConfMenu_Resized)
        except:
            pass
        self.resized.connect(self.AnalyMenu_Resized)

    def set_configMenu(self):
        if hasattr(self, 'toolBar'):
            self.toolBar.close()
        uic.loadUi(self.root_path + 'ui/conf.ui', self)

        # Connect ToolBar
        tb = self.toolBar
        tb.actionTriggered[QAction].connect(self.toolbar_clicked)

        # Print Options
        self.configControl.print_config_data()

        # Connect Button & Layouts
        self.configControl.connect_layouts()

        # Resize 이벤트 연결
        try:
            self.resized.disconnect(self.AnalyMenu_Resized)
        except:
            pass
        self.resized.connect(self.ConfMenu_Resized)

    def resizeEvent(self, event):
        self.resized.emit()
        return super(ToolBarControl, self).resizeEvent(event)

    def AnalyMenu_Resized(self):
        width = self.width()
        height = self.height()

        self.Information.setFixedWidth(width - 20)
        self.Path.setFixedWidth(width - 50)

        self.TabManager.setFixedSize(width - 15, height - 290)

        if self.analysisControl.script_log:
            for log_key in self.analysisControl.script_log:
                self.analysisControl.script_log[log_key].resize(width - 40, height - 330)

        self.PythonScriptBox.setFixedWidth(width - 20)
        self.PythonScriptBox.move(10, height - 160)

        self.PythonScriptList.setFixedWidth(width - 40)
        self.PythonScriptsLog.setFixedWidth(width - 40)

    def ConfMenu_Resized(self):
        width = self.width()
        height = self.height()

        self.DeviceBox.setFixedWidth(width - 20)
        self.AppBox.resize(width - 20, height - 210)

        self.DeviceList.setFixedWidth(width - 120)
        self.iOSList.setFixedWidth(width - 210)

        self.PackageName.setFixedWidth(width - 290)
        self.AppList.resize(width - 40, height - 265)

        self.searchBtn.move(width - 100, 20)
        self.SelDeviceBtn.move(width - 100, 50)
        self.iOSListBtn.move(width - 100, 125)

        self.PackageNameBtn.move(width - 185, 20)
        self.LoadAppListBtn.move(width - 100, 20)

    def closeEvent(self, event):
        print('Frida GUI Tool is closing...')
        if self.analysisControl.device:
            self.analysisControl.device.stop()
