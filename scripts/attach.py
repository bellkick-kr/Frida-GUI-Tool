import traceback

import frida
import sys
import colorama
from colorama import Fore, Back, Style
import random
import argparse
import textwrap

'''
Usage:
# attach to target via USB
python memprint.py -u <target_app_name>

# attach to target with PID
python memprint.py -p <pid>

# attach to target via USB with PID
python memprint.py -u -p <pid>

# attach to target (LOCAL)
python memprint.py <target_app_name>

# enter search strings directly
python memprint.py -u <target_app_name> -s <text>
'''


def on_message(message, data):
    try:
        if message['type'] == 'send':
            # print('%s' % message['payload'])
            for text in message['payload'].split('\n'):
                # self.updatelog('<div style="color: green">%s</div>' % text.replace(' ', '&nbsp;'))
                print(text)
        else:
            print('Error Occured. Pleace check your script.')
            for key, data in message.items():
                print("%s: %s" % (key, data))
    except Exception as e:
        print("Handler Not working")
        print('message:', message)
        print('data:', data)
        traceback.print_exc()

def print_logo():
    logo = """
    스크립트 연결
    """
    bad_colors = ['BLACK', 'WHITE', 'LIGHTBLACK_EX', 'MAGENTA', 'BLUE', 'RESET']
    codes = vars(colorama.Fore)
    colors = [codes[color] for color in codes if color not in bad_colors]
    colored_chars = [random.choice(colors) + char for char in logo]

    print(''.join(colored_chars))


def MENU():
    parser = argparse.ArgumentParser(
        prog='스크립트 연결',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("")
    )

    parser.add_argument('process', help='the process that you will be injecting to')
    parser.add_argument('-p', '--pid', help='attach with pid')
    parser.add_argument('-d', '--device', action='store_true', help='device id to connect')
    parser.add_argument('-l', '--load', help='enter the script file(.js) to attach app')
    args = parser.parse_args()
    return args


if __name__ == '__main__':

    colorama.init()
    print_logo()
    arguments = MENU()

    APP_NAME = arguments.process
    DEVICE = arguments.device
    PID = arguments.pid
    LOAD = arguments.load

    print(Fore.CYAN)

    try:
        session = None
        try:
            if DEVICE and not PID:
                session = frida.get_device(DEVICE, timeout=10).attach(APP_NAME)
                print('[*] Attached to target via USB (%s)' % APP_NAME)
            elif not DEVICE and PID:
                session = frida.attach(int(APP_NAME))
                print('[*] Attached to target with PID (%s)' % APP_NAME)
            elif DEVICE and PID:
                session = frida.get_device(DEVICE, timeout=10).attach(int(APP_NAME))
                print('[*] Attached to target via USB with PID (%s)' % APP_NAME)
            else:
                session = frida.attach(APP_NAME)
                print('[*] Attached to target (%s)' % APP_NAME)
        except:
            print("Can't connect to App. Have you connected the device?")
            sys.exit(0)

        if LOAD:
            script_path = LOAD
            print('| Your script will be loaded [%s]' % script_path)
        else:
            script_path = input('[>] Input the address to read: ')

        print('...')

        # script = session.create_script(run_script(address))
        script = session.create_script(open(script_path, 'r', encoding='utf-8').read())
        script.on('message', on_message)
        script.load()
        # agent = script.exports
        # print('agent: %s' % agent.enumerate_modules())
        sys.stdin.readline()
        # print('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
        session.detach()

    except KeyboardInterrupt:
        sys.exit(0)
