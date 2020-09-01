# -*- coding: utf-8 -*-
import configparser
import subprocess
import traceback
from time import sleep

import frida
from PyQt5.QtWidgets import *

from ui.analysis_option import AnalysisOptionDialog
from util.hookdevice import HookDevice


class AnalysisControl:
    membase = 0x0
    idabase = 0x0
    # pid = 0
    # os_info = ''

    app_name = ''
    package = ''
    ios_list = ''
    device_id = ''

    app_location = ''
    script_path = ''
    tabs = []
    script_log = {}

    def __init__(self, mainWindow, root_path):
        self.device = None
        # self.combined_script = ''
        # self.script_path = os.path.dirname(os.path.abspath(__file__)).replace('ui', '') + 'scripts'
        self.root_path = root_path
        self.mainWindow = mainWindow

    def starthooking_clicked(self):
        """
        후킹 시작 함수
        후킹 시작 버튼 클릭 시 작동
        :return:
        """
        # 후킹 시 마다 옵션 재 확인
        self.hooking_option = self.load_config_file(self.root_path + '/hooking_options.ini')
        
        # 선택된 스크립트 리스트
        will_hook_script = []
        for i in range(0, len(self.hooking_option['Selected Script'])):
            # row = self.Scripts.currentIndex().row()
            saved_script = self.hooking_option['Selected Script']['script_' + str(i)].split(';')
            if saved_script[1] == 'checked':
                will_hook_script.append({'name': saved_script[0], 'path': saved_script[5]})

        if not will_hook_script:
            QMessageBox.about(self.mainWindow, "message", "Please Select Hooking Script.")
            return

        # 자식 / 파생 프로세스 후킹 여부 설정 저장
        options={
            'SpawnGatingCheck': True if self.hooking_option['Gating']['Spawn_Gating'] == 'on' else False,
            'ChildGatingCheck': True if self.hooking_option['Gating']['Child_Gating'] == 'on' else False
        }


        ''' 재 후킹 시 기존 로그 삭제 -> 모든 Tap 삭제 추가해야함'''
        if self.device is not None:
            self.init_tab_manager()
            print(' | Pre-Thread will be closed. %s' % self.device)
            self.script_log[0].append('<div style="color: black"> | Pre-Thread will be closed. %s</div>' % self.device)
            self.device.stop()

        ''' 후킹 준비 '''
        print('# Trying to attach the target app.')
        self.script_log[0].append(' | Trying to attach the target app.')
        # self.mainWindow.ScriptLog.append('| 어플/앱에 연결을 시도합니다.')
        QApplication.processEvents()    # 실시간 로그 출력
        try:
            self.device = HookDevice(gui=self, selected_scripts=will_hook_script, device_id=self.device_id, options=options)
            ''' 다른 Thread 끼리 연결, 안하면 Tab이 새 창에 실행됨
            '   (QObject::setParent: Cannot set parent, new parent is in a different thread)
            '''
            self.device.add_tab.connect(self.tab_add)
        except frida.ServerNotRunningError:
            QMessageBox.about(self.mainWindow, "message", "Check running status of frida-server on your target device.")
            return

        ''' 기존 로그 출력 연결'''
        self.device.write_log.connect(self.write_script_log)

        ''' 후킹 시작 '''
        self.device.start()
        # while not hasattr(self.device, 'session'): #session 유무를 확인한 후 진행해야 오류가 안남
        while not self.device.session:  # session 유무를 확인한 후 진행해야 오류가 안남
            print('APP is not hooked yet.')
            if self.device.error:
                print('FRIDA has ERROR')
                # 전체 내용 업데이트
                self.print_information()
                return
            QApplication.processEvents()
            sleep(1)
        # self.pid = self.device.pid
        # self.os_info = self.device.os_info

        ''' Image Base 구하기 '''
        # print('# Image Base 를 구합니다.')
        try:
            memories = self.device.enumerate_memory_ranges()
            if memories:
                self.membase = memories[0]['base']

            # Set APP Directory
            if self.device.os_info == 'iOS':   # iOS
                for m in memories:
                    if ('file' in m) and ('/Application/' in m['file']['path']):
                        self.app_location = m['file']['path'] + ' | but, it\'s not data path. just app path.'
                        break
                else:
                    self.app_location = 'Sorry, I don\'t know. Find it by typing "find" command on console.'
            elif self.device.os_info == 'Windows': # Windows
                self.app_location = self.package
            else:   # Android
                self.app_location = '/data/data/%s or /data/app/%s' % (self.package, self.package)
        except Exception as e:
            for data in traceback.format_exc().split('\n'):
                # print('%s' % data)
                self.script_log[0].append('<div style="color: red">%s</div>' % data)
                QApplication.processEvents()  # 실시간 로그 출력
            QMessageBox.about(self.mainWindow, "message", "I couldn't get the target app's Image Base beacuse of this Error.")

        # 전체 내용 업데이트
        self.print_information()

    def call_options_setting_dialog(self):
        analysis_options = AnalysisOptionDialog(self.root_path)
        analysis_options.exec_()

    def load_python_scripts(self):
        fname = QFileDialog.getOpenFileName(directory=self.script_path + '/python')
        self.mainWindow.PythonScriptList.clear()
        self.mainWindow.PythonScriptList.addItem(fname[0].split('/')[-1])

    def python_scripts_clicked(self):
        self.mainWindow.PythonScriptsLog.clear()

        item = self.mainWindow.PythonScriptList.item(0)
        if item is not None:
            pythonscript = item.text()
        else:
            QMessageBox.about(self.mainWindow, "message", "Please, Select a python script.")
            return

        print(' | Will be run python script.[%s]' % pythonscript)
        self.mainWindow.PythonScriptsLog.append(' | Run python script on a new console.[%s]' % pythonscript)
        location = self.script_path + '/python/' + pythonscript
        if '.js' in pythonscript:
            exec_script = 'py -3 "%s" -d "%s" -p %d -l "%s"' % (self.script_path + '/attach.py', self.device_id, self.device.pid, location)
        else:
            exec_script = 'py -3 "%s" -d "%s" -p %d' % (location, self.device_id, self.device.pid)
        self.mainWindow.PythonScriptsLog.append(exec_script)

        proc = subprocess.Popen(
            exec_script
            # , stdin=subprocess.PIPE
            # , stdout=subprocess.PIPE
            # , bufsize=1
            , creationflags=subprocess.CREATE_NEW_CONSOLE
            # , shell=True
        )

    def init_tab_manager(self):
        """
        :새 Hooking 시 기존 탭, 로그 삭제 및 재 생성
        :return:
        """
        self.mainWindow.TabManager.clear()
        self.tabs.clear()
        self.script_log.clear()

        self.tabs = [QWidget(self.mainWindow)]
        self.mainWindow.TabManager.addTab(self.tabs[0], 'start')

        self.script_log = {0: QTextBrowser()}
        self.script_log[0].setObjectName('ScriptLog')
        self.script_log[0].setLineWrapMode(QTextBrowser.NoWrap)
        self.script_log[0].horizontalScrollBar().setValue(1)
        layout = QVBoxLayout()
        layout.addWidget(self.script_log[0])
        self.tabs[0].setLayout(layout)

    def tab_add(self, pid):
        """
        :새 PID 생성 시(child / spawn) 로그 Tap 추가 및 연결
        :param pid: 각 Tap 과 연결된 APP PID
        :return:
        """
        self.tabs.append(QWidget(self.mainWindow))
        self.mainWindow.TabManager.addTab(self.tabs[-1], str(pid))
        self.script_log[pid] = QTextBrowser()
        self.script_log[pid].setLineWrapMode(QTextBrowser.NoWrap)
        self.script_log[pid].horizontalScrollBar().setValue(1)

        layout = QVBoxLayout()
        layout.addWidget(self.script_log[pid])
        self.tabs[-1].setLayout(layout)

    def write_script_log(self, pid, message):
        # print('%s %d %s' % (self.script_log, pid, message))
        if pid in self.script_log:
            self.script_log[pid].append(message)
        else:
            self.script_log[0].append('<div style="color: red; font-weight: bold">&nbsp;| Error Occured: PID %d doesn\'t existed.<br>&nbsp;| Error Occured: It would be removed before attached.</div>' % pid)
        QApplication.processEvents()

    def print_information(self, conf=None):
        # Data 설정
        if conf:
            self.app_name = conf['APP']['name']
            self.package = conf['APP']['package']
            self.ios_list = conf['DEFAULT']['ios']
            self.device_id = conf['DEVICE']['id']
            # self.device_info = {'id': conf['DEVICE']['id'], 'type': conf['DEVICE']['type'], 'name': conf['DEVICE']['name']}

        # 출력
        rowposition = self.mainWindow.Information.rowCount()
        self.mainWindow.Information.setItem(rowposition - 1, 0, QTableWidgetItem(self.app_name))
        self.mainWindow.Information.setItem(rowposition - 1, 1, QTableWidgetItem(self.package))
        self.mainWindow.Information.setItem(rowposition - 1, 2, QTableWidgetItem(str(self.membase)))
        self.mainWindow.Information.setItem(rowposition - 1, 3, QTableWidgetItem(str(self.idabase)))
        if self.device:
            self.mainWindow.Information.setItem(rowposition - 1, 4, QTableWidgetItem(str(self.device.pid)))
            self.mainWindow.Information.setItem(rowposition - 1, 5, QTableWidgetItem(self.device.os_info))
            self.mainWindow.Path.setText(self.app_location)
            self.mainWindow.setWindowTitle('Frida GUI Tool :: %s(%s)' % (self.app_name, self.device._device.name))
        self.mainWindow.Information.resizeColumnsToContents()
        # self.mainWindow.Information.horizontalHeader().setStretchLastSection(True)

    def load_config_file(self, path):
        conf = configparser.ConfigParser()
        try:
            conf.read(path, 'utf-8')
        except:
            conf.read(path, 'euc-kr')

        return conf

    def connect_layouts(self):
        self.mainWindow.SetOptionsBtn.clicked.connect(self.call_options_setting_dialog)
        self.mainWindow.StartHooking.clicked.connect(self.starthooking_clicked)
        self.mainWindow.PythonScriptsButton.clicked.connect(self.python_scripts_clicked)
        self.mainWindow.PythonScriptLoad.clicked.connect(self.load_python_scripts)

        # 스크립트 / 프로시져 더블 클릭 시 실행 - 호출한 스크립트/프로시져로 re-attach
        # self.ScriptList.doubleClicked.connect(self.analysisControl.starthooking_clicked)
        self.mainWindow.PythonScriptList.doubleClicked.connect(self.python_scripts_clicked)

        # Tap 연결
        self.mainWindow.analysisControl.script_log[0] = self.mainWindow.ScriptLog
