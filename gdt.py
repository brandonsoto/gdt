import argparse
import subprocess
import sys
import os

DEFAULT_TARGET_IP = "192.168.33.42"
DEFAULT_TARGET_DEBUG_PORT = "8000"
DEFAULT_TARGET_LOGIN = "vagrant"
DEFAULT_TARGET_PASSWORD = "vagrant"
DEFAULT_QNX_SDK = "D:\\Projects\\qnx600"
DEFAULT_GDB = DEFAULT_QNX_SDK + "\\usr\\bin\\ntoarmv7-gdb.exe"
DEFAULT_SYMBOLS = "D:\\Projects\\Symbols"

RETURN_ERROR_FATAL = 1
RETURN_ERROR_TEST_FAILURE = 2
RETURN_SUCCESS = 0

command_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "commands.txt")

def run_gdb():
    try:
        # TODO(brandon): change gdb when ready
        ret = subprocess.call(["gdb", "--command=" + command_file])
        print "Debugging session ended successfully"
    except:
        subprocess.call("reset")
        print "Debugging session ended in an error"
        sys.exit(RETURN_ERROR_FATAL)

def get_service_pid():
    # TODO: implement using nsync
    return 0

def generate_gdb_command_file(args):
    # TODO(brandon): need to add correct arguments to these commands
    file = open(command_file, 'w')
    file.write('file ' + DEFAULT_SYMBOLS + '\n')
    file.write('dir \n')
    file.write('set solib-search-path \n')
    file.write('set auto-solib-add on \n')
    if args.core:
        file.write('core-file ' + args.core + '\n')
    else:
        file.write('target qnx ' + DEFAULT_TARGET_IP + ':' + DEFAULT_TARGET_DEBUG_PORT + '\n')
        file.write('attach ' + str(get_service_pid()))
    file.close()

def validate_args(args):
    global command_file

    if args.core and not args.module:
        print "ERROR: Must specify module when core file is provided"
        sys.exit(RETURN_ERROR_FATAL)

    if args.commands:
        command_file = args.commands
    else:
        generate_gdb_command_file(args)

def parse_args():
    parser = argparse.ArgumentParser(
        description='GDB Developer Tool: developer script to quickly and easily get GDB setup')
    parser.add_argument(
        '-m',
        '--module',
        type=str,
        help="Path to module executable")
    parser.add_argument(
        '-c',
        '--core',
        type=str,
        help="Path to core file (must be used with -m argument)")
    parser.add_argument(
        '-s',
        '--symbols',
        type=str,
        default=DEFAULT_SYMBOLS,
        help="Path to debug symbols")
    parser.add_argument(
        '--commands',
        type=str,
        help="Path to GDB command file (This script will generate its own if not provided)")
    parser.add_argument(
        '-q',
        '--qnx',
        type=str,
        default=DEFAULT_QNX_SDK,
        help="Path to QNX SDK (default: " + DEFAULT_QNX_SDK + ")")
    parser.add_argument(
        '-g',
        '--gdb',
        type=str,
        default=DEFAULT_GDB,
        help="Path to GDB executable (default: " + DEFAULT_GDB + ")")
    args = parser.parse_args()
    return args

def main():
    args = parse_args()
    validate_args(args)
    run_gdb()

if __name__ == '__main__':
    main()