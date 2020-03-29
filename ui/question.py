import os

from PyQt5 import uic
from PyQt5.QtWidgets import QDialog, QPushButton


class QuestionDialog(QDialog):
    def __init__(self, text):
        super(QuestionDialog, self).__init__()
        # self.current_path = os.getcwd()
        self.current_path = os.path.dirname(os.path.abspath(__file__))
        uic.loadUi(self.current_path + '/question.ui', self)
        self.AnswerLayout.setText(text)
        self.adjustSize()

        # 취소 버튼 연결
        self.CloseBtn.setGeometry(self.width() / 2 - 30, self.height() - 30, 75, 20)
        self.CloseBtn.clicked.connect(self.close)
