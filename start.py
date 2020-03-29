# -*- coding: utf-8 -*-
import ctypes
import sys

from PyQt5.QtWidgets import *

from ui.toolbarcontrol import ToolBarControl

if __name__ == '__main__':
    if ctypes.windll.shell32.IsUserAnAdmin():
        print('This Tool is executed as administrator.')
    else:
        print('This Tool is executed as User.')
        print('If your target is Windows Application, this Tool need to run as administrator.')
        print('If your target is Mobile App, this Tool doesn\'t care of it.')

    app = QApplication(sys.argv)

    toolbar_control = ToolBarControl()
    toolbar_control.show()

    sys.exit(app.exec_())
