import argparse
import json
# import nsync
import os
import subprocess
import sys

data = json.load(open('gdt_config.json'))

DEFAULT_TARGET_IP = data["target_ip"]
DEFAULT_TARGET_PASSWORD = data["target_password"]
DEFAULT_TARGET_DEBUG_PORT = data["target_debug_port"]
DEFAULT_QNX_SDK = data["qnx_sdk"]
DEFAULT_GDB = data["gdb_path"]
DEFAULT_SYMBOLS = data["symbols_path"]
DEFAULT_SOLIB_SEARCH_PATH = data["symbols_path"]
DEFAULT_PROJECT_PATH = data["project_path"]

RETURN_ERROR_FATAL = 1

command_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), data["commands_file_name"])


def run_gdb():
    try:
        subprocess.call([DEFAULT_GDB, "--command=" + command_file])
        print "Debugging session ended successfully"
    except Exception as exception:
        subprocess.call("reset")
        print "Debugging session ended in an error: " + exception.message
        sys.exit(RETURN_ERROR_FATAL)


def get_service_pid(ip_address, password, service):
    telnet = nsync.TelnetConnection(ip=ip_address, passwd=password)
    command_output = telnet.sendCommand("ps -A | grep " + service)
    pid_list = command_output.findall(r'\b\d+\b', command_output)
    if len(pid_list) > 0:
        return pid_list[0]
    else:
        return ""


def extract_service_name(service_path):
    return os.path.split(service_path)[1]


def generate_gdb_command_file(args):
    # TODO(brandon): need to figure out best way to generate solib-search-path
    # TODO(brandon): need to search for src directories based on project path - this will generate dir variable
    file = open(command_file, 'w')
    file.write('set solib-search-path ' + args.solib_search_path + '\n')
    file.write('set auto-solib-add on\n')
    file.write('file ' + args.module + '\n')
    if args.core:
        file.write('core-file ' + args.core + '\n')
    else:
        file.write('target qnx ' + args.ip + ':' + args.port_debug + '\n')
        file.write('attach ' + get_service_pid(args.ip, args.password, extract_service_name(args.module)) + '\n')
    file.close()


def validate_args(args):
    if args.core and not args.module:
        print "ERROR: Must specify module when core file is provided"
        sys.exit(RETURN_ERROR_FATAL)


def parse_args():
    parser = argparse.ArgumentParser(
        description='GDB Developer Tool: developer script to quickly and easily debug a remote target or core file.')
    parser.add_argument(
        '-m',
        '--module',
        type=str,
        help="Path to module executable (ends in *.full or *.debug)")
    parser.add_argument(
        '-c',
        '--core',
        type=str,
        help="Path to core file (must be used with -m argument)")
    parser.add_argument(
        '--symbols',
        type=str,
        default=DEFAULT_SYMBOLS,
        help="Path to debug symbols (default: " + DEFAULT_SYMBOLS + ")")
    parser.add_argument(
        '--source',
        type=str,
        help="Paths to source files (default: separate paths with ';')")
    parser.add_argument(
        '--commands',
        type=str,
        help="Path to GDB command file (This script will generate its own if not provided)")
    parser.add_argument(
        '--qnx',
        type=str,
        default=DEFAULT_QNX_SDK,
        help="Path to QNX SDK (default: " + DEFAULT_QNX_SDK + ")")
    parser.add_argument(
        '--gdb',
        type=str,
        default=DEFAULT_GDB,
        help="Path to GDB executable (default: " + DEFAULT_GDB + ")")
    parser.add_argument(
        '--ip',
        type=str,
        default=DEFAULT_TARGET_IP,
        help="Target's IP address (default: " + DEFAULT_TARGET_IP + ")")
    parser.add_argument(
        '--password',
        type=str,
        default=DEFAULT_TARGET_PASSWORD,
        help="Target's login password (default: " + DEFAULT_TARGET_PASSWORD + ")")
    parser.add_argument(
        '--port-debug',
        type=str,
        default=DEFAULT_TARGET_DEBUG_PORT,
        help="Target's debug port (default: " + DEFAULT_TARGET_DEBUG_PORT + ")")
    parser.add_argument(
        '--solib-search-path',
        type=str,
        default=DEFAULT_SOLIB_SEARCH_PATH,
        help="Target's debug port (default: " + DEFAULT_SOLIB_SEARCH_PATH + ")")
    parser.add_argument(
        '--project-path',
        type=str,
        default=DEFAULT_PROJECT_PATH,
        help="Path to the project (default: " + DEFAULT_PROJECT_PATH + ")")
    args = parser.parse_args()
    return args


def main():
    global command_file

    args = parse_args()
    validate_args(args)

    if args.commands:
        command_file = args.commands
    else:
        generate_gdb_command_file(args)

    run_gdb()


if __name__ == '__main__':
    main()
