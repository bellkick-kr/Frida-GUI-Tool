# -*- coding: utf-8 -*-
import threading
import traceback
from collections import OrderedDict

import frida
from PyQt5.QtCore import QThread, pyqtSignal


class HookDevice(QThread):
    write_log = pyqtSignal(int, str)
    add_tab = pyqtSignal(int)
    log_event = threading.Event()
    pid = 0
    error = False
    js = ''
    session = {}

    def __init__(self, gui=None, selected_scripts=None, device_id=None, options=None):
        QThread.__init__(self)
        # self.gui = gui.mainWindow

        if device_id == 'local':
            self.package = gui.package.replace('/', '\\')
        else:
            self.package = gui.package
        self.app_name = gui.app_name
        self.script_path = gui.script_path
        self.selected_scripts = selected_scripts
        self.options = options

        ''' 연결할 단말을 찾는다. '''
        self._device = frida.get_device(device_id, timeout=10)

        ''' iOS / Android / Window Device 분류 '''
        for d in gui.ios_list.replace(' ', '').split(','):
            if d in self._device.name:
                self.os_info = 'iOS'
                break
        else:
            self.os_info = 'Android' if device_id != 'local' else 'Windows'

        ''' APP이 실행 중인 경우 PID 획득 => 실행 중인 APP은 Attache / 아니면 SPAWN 하기 위함'''
        proc_list = self._device.enumerate_applications() if self._device.id != 'local' else self._device.enumerate_processes()
        for app in proc_list:
            if app.name == self.app_name:
                # print('-', app.name)
                self.pid = app.pid
                break

    def run(self):
        """
        Hooking Thread의 시작 Method
        순서: HookDevice:init() -> run() -> 반복: _instrument, _on_child_added, _on_spawn_added
        :return:
        """
        self.combine_typescripts(self.selected_scripts)

        try:
            # print(self.gate_hooking_onoff)
            if self.options['SpawnGatingCheck']:
                ''' 새 PROCESS 생성 유무 확인 '''
                if self._device.id != 'local':
                    ''' Window에서 아직 지원 안함(frida 12.6.8 기준) -> Window는 별도의 프로세스가 아닌 자식 프로세스를 생성함
                    '   frida.NotSupportedError: not yet supported on this OS( tested frida 12.6.8)
                    '''
                    # self.pre_pid = self.pid # Spawn-added 일 경우 이전 PROC 정보가 없기 때문에 별도 저장
                    self._device.on("spawn-added", self._on_spawn_added)
                    self._device.on("spawn-removed", self._on_spawn_removed)
                    self.updatelog(0, "✔ enable_spawn_gating()")
                    self._device.enable_spawn_gating()
                else:
                    self.updatelog(0, "X impossible_spawn_gating: spawn_gating is impossible during Windows Analysis.")
            if self.options['ChildGatingCheck']:
                ''' Child Proccess는 Android, iOS, PC 모두 생성함 '''
                self._device.on("child-added", self._on_child_added)
                self._device.on("child-removed", self._on_child_removed)
                self._device.enumerate_pending_children()
            if self.options['SpawnGatingCheck'] and self.options['ChildGatingCheck']:
                self.updatelog(0, '<div style="color: red">&nbsp;| Caution: If Spawn_Gating and Child_Gating options are set together,<br>&nbsp;| Caution: it would be occured some error.</div>')

            if self.pid == 0:  # APP 이 실행 중이지 않은 경우
                # print("✔ spawn(argv=%s)" % self.package)
                self.updatelog(0, "✔ spawn(argv=%s)" % self.package)
                self.pid = self._device.spawn(self.package)
                self._instrument(self.pid, True)
            else:
                self.add_tab.emit(self.pid)  # Tab 생성
                self.updatelog(self.pid, "X spawn(argv=%s): Already running the target app." % self.package)
                self._instrument(self.pid, False)

        except Exception:
            self.error = True
            self.updatelog(0, '<div style="color: red; font-weight: bold">&nbsp;| Error occured: If your target is a Windows Application, this tool need to be runned as administrator.</div>')
            self.updatelog(0, '<div style="color: red; font-weight: bold">&nbsp;| Error occured: Or, Try to check your frida-server on your target deivce.</div>')
            self.updatelog(0, '<div style="color: red">' + traceback.format_exc().replace('\n', '<br>') + '</div>')

    def _instrument(self, pid, resume):
        # pid = proc.pid
        try:
            ''' New Tab 생성(gating 또는 spawn 시에만, attach는 바로 앞에서 이미 함) '''
            if resume:
                self.add_tab.emit(pid)

            ''' Frida Attaches to APP '''
            self.session[pid] = self._device.attach(pid)
            # self._device.enumerate_pending_children()
            self.updatelog(pid, "✔ attach(pid=%d)" % pid)
            self.session[pid].on("detached", lambda reason: self._on_detached(pid, reason))

            ''' Child Gating: Child Process 탐지'''
            if self.options['ChildGatingCheck']:
                self.updatelog(pid, "✔ enable_child_gating()")
                self.session[pid].enable_child_gating()

            # print("✔ create_script()")
            self.updatelog(pid, "✔ create_script()")
            script = self.session[pid].create_script(self.js)

            script.on("message", lambda message, data: self._on_message(pid, message))
            # print("✔ load()")
            self.updatelog(pid, "✔ script.load(%s)" % self.selected_scripts)
            script.load()

            if resume:
                # print("✔ resume(pid=%d)" % pid)
                self.updatelog(pid, "✔ resume(pid=%d): I will run the APP" % pid)
                self._device.resume(pid)
            else:
                self.updatelog(pid, "X resume(pid=%d): Already running, trying to Attach" % pid)
            # self._sessions.add(session)
        except Exception:
            self.error = True
            self.updatelog(0, '<div style="color: red; font-weight: bold">&nbsp;| Error occured: If your target is a Windows Application, this tool need to be runned as administrator.</div>')
            self.updatelog(0, '<div style="color: red; font-weight: bold">&nbsp;| Error occured: Or, Try to check your frida-server on your target deivce.</div>')
            # self.updatelog(0, '<div style="color: red; font-weight: bold">&nbsp;| Error occured: EQda는 frida 12.6.8로 제작했습니다.</div>')
            self.updatelog(0, '<div style="color: red">' + traceback.format_exc().replace('\n', '<br>') + '</div>')

    def _on_child_added(self, child):
        # print("⚡ child_added: %s" % child)
        self.updatelog(child.parent_pid, "⚡ child_added: %s" % str(child).replace(',', ',<br>&nbsp;| '))
        self.updatelog(0, "⚡ child_added: %s" % str(child).replace(',', ',<br>&nbsp;| '))
        self._instrument(child.pid, True)
        # if child.identifier == self.package and child.pid != self.pid:
        #     self._instrument(child.pid, True)

    def _on_child_removed(self, child):
        self.updatelog(child.pid, "⚡ child_removed: %s" % str(child).replace(',', ',<br>&nbsp;| '))
        self.updatelog(0, "⚡ child_removed: %s" % str(child).replace(',', ',<br>&nbsp;| '))
        # self.session[child.pid].detach()
        if child.pid not in self.session:
            print('Attach 전 remove 되었습니다. %d' % child.pid)
            self.updatelog(0, '<div style="color: red; font-weight: bold">⚡ Error Occured: child_removed</div>')
            self.updatelog(0, '<div style="color: red; font-weight: bold">⚡ Tried removing before attach: %d</div>' % child.pid)
        else:
            del self.session[child.pid]

    def _on_spawn_added(self, proc):
        self.updatelog(0, "⚡ spawn_added: %s" % str(proc))
        if proc.identifier == self.package and proc.pid != self.pid:
            self._instrument(proc.pid, True)

    def _on_spawn_removed(self, proc):
        self.updatelog(0, "⚡ spawn_removed: %s" % str(proc))
        self.updatelog(proc.pid, "⚡ spawn_removed: %s" % str(proc))
        # self.session[proc.pid].detach()
        del self.session[proc.pid]

    def _on_detached(self, pid, reason):
        # print("⚡ detached: pid={}, reason='{}'".format(pid, reason))
        self.updatelog(pid, "⚡ detached: %s" % reason)
        del self.session[pid]
        print(' | %d Detached: %s' % (pid, str(self.session)))

    def _on_message(self, pid, message):
        if message['type'] == 'error':
            self.updatelog(pid, '<div style="color: red">&nbsp;| Error occured: Please, Check your hooking scripts.</div>')
            self.updatelog(pid, '<div style="color: red">&nbsp;| Loaded Script: %s</div>' % self.selected_scripts)
            for key, data in message.items():
                # print('%s: %s' % (key, data))
                self.updatelog(pid, '<div style="color: red">%s: %s</div>' % (key, data))
        elif message['type'] == 'send':
            if type(message['payload']) is not str:
                message['payload'] = str(message['payload'])
            self.updatelog(pid, '<div style="color: green">⚡ MSG=%s</div>' % message['payload'].replace('\n', '<br>'))
        else:
            self.updatelog(pid, '%s' % str(message))

    def stop(self):
        self.log_event.clear()
        self.session.clear()
        print('Every Session is stopped:', self.session)
        print('Hooking Sessions are detached')
        # self.terminate() - kill 같은 애, DOCS에서 권고 안한다니 안씀
        self.quit()
        # self.wait() - quit -> wait 같이 쓰면 화면 종료시 에러나는 듯(quit에서 wait하는 건가)
        print('Device hooking thread is quit')

    def combine_typescripts(self, script_list):
        """ 선택된 스크립트를 하나로 결합
        "   에러 발생 시 결합된 최종 스크립트의 라인 번호가 찍히니 고려해야함
        "   최종 스크립트.ts를 tmp에 생성할 까 고민 중
        """
        # print('| 선택한 스크립트들을 하나로 합칩니다.')
        self.updatelog(0, '✔ combine_typescripts:')
        scripts = ''
        for script_info in script_list:
            print(' | Combine: %s' % script_info)
            self.updatelog(0, ' | Combine: %s' % script_info)
            js = open(script_info['path'], 'r', encoding='utf-8').read()
            scripts += js + '\n'
        self.js = scripts

    def enumerate_memory_ranges(self):
        # 후킹코드를 injection한다.
        script = self.session[list(self.session.keys())[0]].create_script('''
                rpc.exports = {
                  enumerateRanges: function (prot) {
                    return Process.enumerateRangesSync(prot);
                  }
                }''')
        # print(js)
        # script.on('message', self.on_message)
        script.load()
        agent = script.exports
        ranges = agent.enumerate_ranges('---')

        # self.updatelog(0, '메모리에 탑재된 파일들:')
        # files = [memory['file']['path'] for memory in ranges if 'file' in memory]
        # files = list(OrderedDict.fromkeys(files))

        return ranges

    def updatelog(self, pid, text):
        # print([pid, text])
        self.log_event.set()
        self.write_log.emit(pid, text)
        self.log_event.wait(2)
        # self.wait(100)
        ''' spawn_gating 시 여러 PID에서 보내서 그런지 원인 모를 종료가 발생함
        '   해결방안으로 wait() 시도 중
        '''
        self.msleep(100)  # ※주의 QThread에서 제공하는 sleep을 사용