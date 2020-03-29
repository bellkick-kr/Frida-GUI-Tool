import frida
import sys
import colorama
from colorama import Fore, Back, Style
import random
import argparse
import textwrap


def on_message(message, data):
    print(message)


def print_logo():
    logo = """
    Image Base 구하기
    """
    bad_colors = ['BLACK', 'WHITE', 'LIGHTBLACK_EX', 'MAGENTA', 'BLUE', 'RESET']
    codes = vars(colorama.Fore)
    colors = [codes[color] for color in codes if color not in bad_colors]
    colored_chars = [random.choice(colors) + char for char in logo]

    print(''.join(colored_chars))


def MENU():
    parser = argparse.ArgumentParser(
        prog='Image Base',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("")
    )

    parser.add_argument('process', help='the process that you will be injecting to')
    parser.add_argument('-p', '--pid', action='store_true', help='attach with pid')
    parser.add_argument('-d', '--device', action='store_true', help='device id to connect')
    parser.add_argument('-a', '--addr', help='enter the address what you want to print')
    args = parser.parse_args()
    return args


def run_script():
    script_code = """
    Process.enumerateModules({
        onMatch: function(module){
            console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString());
        }, 
        onComplete: function(){}
    });
    """
    return script_code


if __name__ == '__main__':

    colorama.init()
    print_logo()
    arguments = MENU()

    APP_NAME = arguments.process
    DEVICE = arguments.device
    PID = arguments.pid
    ADDR = arguments.addr

    print(Fore.CYAN)

    try:
        session = None
        try:
            if DEVICE and not PID:
                session = frida.get_usb_device(timeout=10).attach(APP_NAME)
                print('[*] Attached to target via DEVICE (%s)' % APP_NAME)
            elif not DEVICE and PID:
                session = frida.attach(int(APP_NAME))
                print('[*] Attached to target with PID (%s)' % APP_NAME)
            elif DEVICE and PID:
                session = frida.get_usb_device(timeout=10).attach(int(APP_NAME))
                print('[*] Attached to target via DEVICE with PID (%s)' % APP_NAME)
            else:
                session = frida.attach(APP_NAME)
                print('[*] Attached to target (%s)' % APP_NAME)
        except:
            print("Can't connect to App. Have you connected the device?")
            sys.exit(0)

        # if ADDR:
        #     address = ADDR
        #     print('[>] The address to read: ' + address)
        # else:
        #     address = input('[>] Input the address to read: ')

        print('')

        # script = session.create_script(run_script(address))
        script = session.create_script(run_script())
        script.on('message', on_message)
        script.load()
        agent = script.exports
        print('agent: %s' % agent.enumerate_modules())
        sys.stdin.readline()
        # print('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
        session.detach()

    except KeyboardInterrupt:
        sys.exit(0)
