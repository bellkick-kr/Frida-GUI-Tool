# -*- coding: utf-8 -*-

import configparser
import subprocess
import traceback

import frida
from PyQt5 import QtCore
from PyQt5.QtWidgets import QTableWidgetItem, QMessageBox, QFileDialog, QPushButton


class ConfigControl:
    def __init__(self, mainWindow, root_path):
        self.mainWindow = mainWindow
        self.root_path = root_path

    def connect_layouts(self):
        # Connect Button
        self.mainWindow.searchBtn.clicked.connect(self.print_devices)
        self.mainWindow.SelDeviceBtn.clicked.connect(self.device_selected)
        self.mainWindow.iOSListBtn.clicked.connect(self.ios_list_btn_clicked)

        self.mainWindow.ScriptEditSaveBtn.clicked.connect(self.save_script_edit_program)

        self.mainWindow.PackageNameBtn.clicked.connect(self.package_name_btn_clicked)
        self.mainWindow.LoadAppListBtn.clicked.connect(self.get_app_proclist)

        # Connect Layout
        self.mainWindow.DeviceList.doubleClicked.connect(self.device_selected)
        self.mainWindow.AppList.doubleClicked.connect(self.applist_dblclicked)

    def print_config_data(self):
        # Load Config File
        self.target_options = self.load_config_file(self.root_path + 'target_options.ini')

        # Print the name of Main Window & Selected Device Info
        if self.target_options['DEVICE']['NAME']:
            self.mainWindow.setWindowTitle('EQda :: %s - Setting Options' % self.target_options['DEVICE']['name'])
            self.mainWindow.DeviceLabel.setText('Selected Device: %s' % {'Name': self.target_options['DEVICE']['name'],
                                                                         'Connection': self.target_options['DEVICE']['type'],
                                                                         'ID': self.target_options['DEVICE']['id']
                                                                         })
        else:
            self.mainWindow.setWindowTitle('EQda - Setting Options')
            self.mainWindow.DeviceLabel.setText('Selected Device: None')

        # Print Connected Device List
        self.print_devices()

        # Print Option Values
        ios_list = self.target_options['DEFAULT']['ios'] if self.target_options['DEFAULT']['ios'] is not None and self.target_options['DEFAULT']['ios'] != '' else 'None'
        self.mainWindow.iOSList.setText(ios_list)

        self.mainWindow.ScriptEditProgram.setText(self.target_options['DEFAULT']['script edit program'])

        package = '%s - %s' % (self.target_options['APP']['name'], self.target_options['APP']['package']) \
            if self.target_options['APP']['package'] is not None and self.target_options['APP']['package'] != '' \
            else 'EMPTY' if self.target_options['DEVICE']['id'] != 'local' \
            else self.target_options['APP']['name']
        self.mainWindow.PackageName.setText(package)

    def device_selected(self):
        try:
            selected_device_id = self.mainWindow.DeviceList.selectionModel().selectedIndexes()[0].data()
            selected_device_type = self.mainWindow.DeviceList.selectionModel().selectedIndexes()[1].data()
            selected_device_name = self.mainWindow.DeviceList.selectionModel().selectedIndexes()[2].data()
        except IndexError as e:
            QMessageBox.about(self.mainWindow, "message", "Please, Select your Device")
            return

        self.target_options.set('DEVICE', 'id', selected_device_id)
        self.target_options.set('DEVICE', 'type', selected_device_type)
        self.target_options.set('DEVICE', 'name', selected_device_name)

        configfile = open(self.root_path + 'target_options.ini', 'w')
        self.target_options.write(configfile)
        configfile.close()
        QMessageBox.about(self.mainWindow, "message", "%s was Selected" % selected_device_name)

        self.print_config_data()

    def ios_list_btn_clicked(self):
        ios_list = self.mainWindow.iOSList.text()
        self.target_options.set(None, 'ios', ios_list)
        configfile = open(self.root_path + 'target_options.ini', 'w')
        self.target_options.write(configfile)
        configfile.close()

    def save_script_edit_program(self):
        program = self.mainWindow.ScriptEditProgram.text()
        self.target_options.set(None, 'script edit program', program)
        configfile = open(self.root_path + 'target_options.ini', 'w')
        self.target_options.write(configfile)
        configfile.close()

    def package_name_btn_clicked(self):
        try:
            name, package = self.mainWindow.PackageName.text().split(' - ')
            self.target_options.set('APP', 'name', name)
            self.target_options.set('APP', 'package', package)
            configfile = open(self.root_path + 'target_options.ini', 'w')
            self.target_options.write(configfile)
            configfile.close()

            msgBox = QMessageBox()
            msgBox.setWindowTitle('EQda :: %s' % name)
            msgBox.setText("Target APP(%s) is saved in target_options.ini\nIf you analyze the app, Move to analysis tab." % name)
            # msgBox.setText("Target APP(%s)이 설정파일에 저장되었습니다.\n진단을 하시려면 분석 탭으로 이동하세요." % name)
            msgBox.addButton(QPushButton('Move to Analysis Tab.'), QMessageBox.ActionRole)
            msgBox.addButton(QPushButton('Open target_options.ini'), QMessageBox.AcceptRole)
            {
                0: self.mainWindow.set_analysisMenu,
                1: lambda: subprocess.Popen(r'%s "%s"' % (self.target_options['DEFAULT']['script edit program'], str(self.root_path + 'target_options.ini')))
            }[msgBox.exec_()]()
        except Exception as e:
            QMessageBox.about(self.mainWindow, "message", "Error Occured.: %s" % e)
            traceback.print_exc()

    def applist_dblclicked(self):
        if self.target_options['DEVICE']['id'] == 'local':
            data = self.mainWindow.AppList.selectionModel().selectedIndexes()[1].data() + ' - '
        else:
            data = self.mainWindow.AppList.selectionModel().selectedIndexes()[1].data() + ' - ' + self.mainWindow.AppList.selectionModel().selectedIndexes()[2].data()
        self.mainWindow.PackageName.setText(data)

    def get_app_proclist(self):
        device = frida.get_device(self.target_options['DEVICE']['id'], timeout=10)

        try:
            ''' Windows - get Processes / Mobile - get Applications'''
            proc_list = device.enumerate_applications() if device.id != 'local' else device.enumerate_processes()
            for i, proc in enumerate(proc_list):
                self.mainWindow.AppList.insertRow(i)
                item = QTableWidgetItem('-' if proc.pid == 0 else str(proc.pid))
                item.setTextAlignment(QtCore.Qt.AlignHCenter)
                self.mainWindow.AppList.setItem(i, 0, item)
                item = QTableWidgetItem(proc.name)
                item.setTextAlignment(QtCore.Qt.AlignHCenter)
                self.mainWindow.AppList.setItem(i, 1, item)
                if hasattr(proc, 'identifier'):
                    self.mainWindow.AppList.setItem(i, 2, QTableWidgetItem(proc.identifier))

            self.mainWindow.AppList.resizeColumnsToContents()
            self.mainWindow.AppList.horizontalHeader().setStretchLastSection(True)
        except frida.ServerNotRunningError:
            QMessageBox.about(self.mainWindow, "message", "Check running status of frida-server on your target device.")
            return

        ''' Local System(Window)인 경우, 설치된 파일에서 선택 '''
        if device.id == 'local':
            fname = QFileDialog.getOpenFileName()
            package = fname[0]
            name = fname[0].split('/')[-1]
            self.mainWindow.PackageName.setText(name + ' - ' + package)

    def print_devices(self):
        self.mainWindow.DeviceList.setRowCount(0)
        device_list = frida.get_device_manager().enumerate_devices()

        i = 0
        length = len(device_list)
        while i < length:
            if device_list[i].name == 'Local TCP':
                del device_list[i]
                break
            else:
                i += 1

        for i, device in enumerate(device_list):
            self.mainWindow.DeviceList.insertRow(i)
            self.mainWindow.DeviceList.setItem(i, 0, QTableWidgetItem(device.id))
            self.mainWindow.DeviceList.setItem(i, 1, QTableWidgetItem(device.type))
            self.mainWindow.DeviceList.setItem(i, 2, QTableWidgetItem(device.name))
        self.mainWindow.DeviceList.resizeColumnsToContents()
        self.mainWindow.DeviceList.horizontalHeader().setStretchLastSection(True)

    def load_config_file(self, file_path):
        conf = configparser.ConfigParser()
        try:
            conf.read(file_path, 'utf-8')
        except:
            conf.read(file_path, 'euc-kr')

        return conf
