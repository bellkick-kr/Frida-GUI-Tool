import configparser
import os
import subprocess

from PyQt5 import uic
from PyQt5.QtCore import QDir
from PyQt5.QtWidgets import QDialog, QFileSystemModel, QAbstractItemView, \
    QTableWidgetItem, QCheckBox

from ui.question import QuestionDialog


class AnalysisOptionDialog(QDialog):
    def __init__(self, root_path):
        super(AnalysisOptionDialog, self).__init__()
        # self.current_path = os.getcwd()
        self.hooking_options_path = root_path + 'hooking_options.ini'
        self.conf = self.load_config_file(self.hooking_options_path)
        self.script_edit_program_path = self.load_config_file(root_path + 'target_options.ini')['DEFAULT']['script edit program']
        uic.loadUi(root_path + 'ui/analysis_option.ui', self)

        self.script_directory_path = root_path + 'scripts/typescript/'
        self.dirModel = QFileSystemModel()
        self.dirModel.setRootPath(self.script_directory_path)
        self.dirModel.setFilter(QDir.NoDotAndDotDot | QDir.AllDirs)

        self.fileModel = QFileSystemModel()
        self.fileModel.setFilter(QDir.NoDotAndDotDot | QDir.Files)

        self.Directories.setModel(self.dirModel)
        self.Scripts.setModel(self.fileModel)

        self.Directories.setRootIndex(self.dirModel.index(self.script_directory_path))
        self.Scripts.setRootIndex(self.fileModel.index(self.script_directory_path))

        self.Directories.resizeColumnToContents(1)
        self.Directories.resizeColumnToContents(3)
        header = self.Scripts.horizontalHeader()
        header.setSectionResizeMode(0, header.ResizeToContents)
        header.setSectionResizeMode(1, header.ResizeToContents)
        header.setSectionResizeMode(2, header.ResizeToContents)
        self.Scripts.setSelectionBehavior(QAbstractItemView.SelectRows)

        header = self.SelectedScript.horizontalHeader()
        header.setSectionResizeMode(0, header.ResizeToContents)
        # header.setSectionResizeMode(1, header.Fixed)
        self.SelectedScript.setColumnWidth(1, 60)
        header.setSectionResizeMode(2, header.ResizeToContents)
        header.setSectionResizeMode(3, header.ResizeToContents)
        header.setSectionResizeMode(4, header.ResizeToContents)
        header.setSectionResizeMode(5, header.ResizeToContents)

        self.print_saved_options()

        # 클릭 이벤트 연결
        self.Directories.clicked.connect(self.print_script_list)
        self.Directories.doubleClicked.connect(self.open_directory)
        self.Scripts.doubleClicked.connect(self.script_selected)
        self.DisSelectBtn.clicked.connect(self.deselect_script)
        self.ScriptSaveBtn.clicked.connect(self.save_options)
        self.SelectedScript.doubleClicked.connect(self.edit_selected_script)
        self.EtcOptionSaveBtn.clicked.connect(self.save_etc_options)
        self.CancelBtn.clicked.connect(self.close)
        self.DirQuestionBtn.clicked.connect(self.dir_question)
        self.ScriptQuestionBtn.clicked.connect(self.script_question)

    def script_selected(self):
        # row = self.Scripts.currentIndex().row()
        rowPosition = self.SelectedScript.rowCount()
        self.SelectedScript.insertRow(rowPosition)
        self.SelectedScript.setItem(rowPosition, 0, QTableWidgetItem(self.Scripts.selectedIndexes()[0].data()))
        chk_bx = QCheckBox()
        chk_bx.setStyleSheet("margin-left:23;")
        self.SelectedScript.setCellWidget(rowPosition, 1, chk_bx)
        self.SelectedScript.setItem(rowPosition, 2, QTableWidgetItem(self.Scripts.selectedIndexes()[1].data()))
        self.SelectedScript.setItem(rowPosition, 3, QTableWidgetItem(self.Scripts.selectedIndexes()[2].data()))
        self.SelectedScript.setItem(rowPosition, 4, QTableWidgetItem(self.Scripts.selectedIndexes()[3].data()))
        self.SelectedScript.setItem(rowPosition, 5, QTableWidgetItem(self.script_directory_path + self.Directories.selectedIndexes()[0].data() + '/' + self.Scripts.selectedIndexes()[0].data()))

    def deselect_script(self):
        self.SelectedScript.removeRow(self.SelectedScript.currentRow())

    def save_options(self):
        allrows = self.SelectedScript.rowCount()
        self.conf.remove_section('Selected Script')
        self.conf.add_section('Selected Script')

        i = 0
        while i < allrows:
            self.conf.set('Selected Script', 'script_' + str(i), '%s;%s;%s;%s;%s;%s' % (
                self.SelectedScript.item(i, 0).text(),
                'checked' if self.SelectedScript.cellWidget(i, 1).isChecked() else 'unchecked',
                self.SelectedScript.item(i, 2).text(),
                self.SelectedScript.item(i, 3).text(),
                self.SelectedScript.item(i, 4).text(),
                self.SelectedScript.item(i, 5).text()
            ))
            configfile = open(self.hooking_options_path, 'w')
            self.conf.write(configfile)
            configfile.close()
            i += 1

    def edit_selected_script(self):
        row = self.SelectedScript.currentRow()
        subprocess.Popen(r'%s "%s"' % (self.script_edit_program_path, self.SelectedScript.item(row, 5).text()))

    def save_etc_options(self):
        self.conf['Gating']['Spawn_Gating'] = 'on' if self.SpawnGatingCheck.isChecked() else 'off'
        self.conf['Gating']['Child_Gating'] = 'on' if self.ChildGatingCheck.isChecked() else 'off'

        configfile = open(self.hooking_options_path, 'w')
        self.conf.write(configfile)
        configfile.close()

    def load_config_file(self, path):
        conf = configparser.ConfigParser()
        try:
            conf.read(path, 'utf-8')
        except:
            conf.read(path, 'euc-kr')

        return conf

    def print_saved_options(self):
        for i in range(0, len(self.conf['Selected Script'])):
            # row = self.Scripts.currentIndex().row()
            saved_script = self.conf['Selected Script']['script_' + str(i)].split(';')
            self.SelectedScript.insertRow(i)
            self.SelectedScript.setItem(i, 0, QTableWidgetItem(saved_script[0]))
            chk_bx = QCheckBox()
            chk_bx.setChecked(True if saved_script[1] == 'checked' else False)
            chk_bx.setStyleSheet("margin-left:23;")
            self.SelectedScript.setCellWidget(i, 1, chk_bx)
            self.SelectedScript.setItem(i, 2, QTableWidgetItem(saved_script[2]))
            self.SelectedScript.setItem(i, 3, QTableWidgetItem(saved_script[3]))
            self.SelectedScript.setItem(i, 4, QTableWidgetItem(saved_script[4]))
            self.SelectedScript.setItem(i, 5, QTableWidgetItem(saved_script[5]))

        self.SpawnGatingCheck.setChecked(True if self.conf['Gating']['Spawn_Gating'] == 'on' else False)
        self.ChildGatingCheck.setChecked(True if self.conf['Gating']['Child_Gating'] == 'on' else False)

    def print_script_list(self, index):
        path = self.dirModel.fileInfo(index).absoluteFilePath()
        self.Scripts.setRootIndex(self.fileModel.setRootPath(path))

    def open_directory(self, index):
        path = self.dirModel.fileInfo(index).absoluteFilePath()
        os.startfile(path)

    def dir_question(self):
        text = '1. click: Select the directory and show files in directory at right layout\n' \
               '2. double click: Open the directory by explorer'
        questionDialog = QuestionDialog(text)
        questionDialog.exec_()

    def script_question(self):
        text = '1. Save Button click: Save selected scripts options in hooking_options.ini\n' \
               '2. Delete Button click: Delete the selected script row\n' \
               '3. Script Double click: Edit the selected script on your script edit program(set in target_options.ini)'
        questionDialog = QuestionDialog(text)
        questionDialog.exec_()
