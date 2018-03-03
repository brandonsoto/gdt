#!/usr/bin/python

import argparse
import json
import os
import re
import socket
import subprocess
import telnetlib

INFO_COLOR = '\033[95m'
SUCCESS_COLOR = '\033[92m'
FAIL_COLOR = '\033[91m'
END_COLOR = '\033[0m'


def print_info(string):
    print INFO_COLOR + string + END_COLOR


def print_success(string):
    print SUCCESS_COLOR + string + END_COLOR


def print_failure(string):
    print FAIL_COLOR + string + END_COLOR


def get_str_repr(string):
    return repr(str(string))[1:-1]


def verify_path_exists(path, path_exists):
    if path and not path_exists(path):
        raise Exception("path does not exist - " + path)


def verify_dir_exists(path):
    verify_path_exists(path, os.path.isdir)


def verify_file_exists(path):
    verify_path_exists(path, os.path.isfile)


def generate_search_path(root_path, excluded_dirs, unary_func, separator):
    search_path = []
    for root, dirs, files in os.walk(root_path, topdown=True):
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        if any(unary_func(f) for f in files):
            search_path.insert(0, get_str_repr(os.path.abspath(root)))
    return separator.join(search_path)


def generate_solib_search_path(symbol_paths, excluded_dirs):
    separator = ";"
    solib_search_paths = [generate_search_path(path, excluded_dirs, is_shared_library, separator) for path in symbol_paths]
    return separator.join(solib_search_paths)


def generate_source_search_path(root_path, excluded_dirs, is_qnx_target):
    return generate_search_path(root_path, excluded_dirs, is_cpp_file, ";" if is_qnx_target else ":")


def is_shared_library(path):
    lib_number = re.search(r'\d+$', path)
    file_extension = ".so"
    if lib_number:
        file_extension += "." + lib_number.group()
    return path.endswith(file_extension)


def is_cpp_file(path):
    return any(path.endswith(extension) for extension in [".cpp", ".c", ".cc", ".h", ".hpp"])


class Config:
    def __init__(self, args):
        data = json.load(open('gdt_config.json'))

        self.program_path = args.program
        self.core_path = args.core
        self.is_qnx_target = not args.other_target
        self.symbol_paths = data["symbol_paths"]
        self.generate_command_file = not args.command
        self.command_file = args.command if args.command else os.path.join(os.path.dirname(os.path.abspath(__file__)), "gdb_commands.txt")
        self.target_ip = data["target_ip"]
        self.target_user = data["target_user"]
        self.target_password = data["target_password"]
        self.target_debug_port = data["target_debug_port"]
        self.target_prompt = data["target_prompt"]
        self.gdb_path = data["gdb_path"]
        self.project_path = data["project_root"]
        self.solib_search_path = ""
        self.source_search_path = ""
        self.excluded_dirs = data["excluded_dirs"]
        self.breakpoint_file = args.breakpoints if args.breakpoints else data["breakpoints"]

        self.validate()
        self.init_paths()

    def validate(self):
        print_info('Validating configuration...')

        for file_path in [self.program_path, self.core_path, self.gdb_path, self.command_file if not self.generate_command_file else None, self.breakpoint_file]:
            verify_file_exists(file_path)

        for dir_path in self.symbol_paths + [self.project_path]:
            verify_dir_exists(dir_path)

        print_success('Validated configuration successfully!')

    def init_paths(self):
        print_info('Generating search paths...')

        if self.program_path:
            self.program_path = get_str_repr(os.path.abspath(self.program_path))

        if self.core_path:
            self.core_path = get_str_repr(os.path.abspath(self.core_path))

        if self.breakpoint_file:
            self.breakpoint_file = get_str_repr(os.path.abspath(self.breakpoint_file))

        self.solib_search_path = generate_solib_search_path(self.symbol_paths, self.excluded_dirs)
        self.source_search_path = generate_source_search_path(self.project_path, self.excluded_dirs, self.is_qnx_target)
        self.project_path = get_str_repr(os.path.abspath(self.project_path))
        self.gdb_path = os.path.abspath(self.gdb_path)

        print_success('Generated search paths successfully!')


# thanks to Blayne Dennis for this class
class TelnetConnection:
    def __init__(self, ip, user, password, prompt):
        self.TIMEOUT_SEC = 10
        self.PORT = 23
        self.ip = ip
        self.user = user
        self.password = password
        self.session = None
        self.prompt = prompt
        self.connect()

    def __del__(self):
        self.close()

    def close(self):
        if self.session:
            self.session.close()

    def read_response(self, prompt):
        return self.session.read_until(prompt, self.TIMEOUT_SEC)

    def connect(self):
        try:
            self.session = telnetlib.Telnet(self.ip, self.PORT, self.TIMEOUT_SEC)
        except (socket.timeout, socket.error):
            raise Exception("Telnet: Server doesn't respond")

        self.read_response('login: ')
        self.session.write('{}\n'.format(self.user))
        self.read_response('Password: ')
        self.session.write('{}\n'.format(self.password))
        resp = self.read_response(self.prompt)
        if resp[-len(self.prompt):] != self.prompt:
            raise Exception('Telnet: Username or password invalid')

    def send_command(self, cmd):
        self.session.write('{}\n'.format(cmd))
        return self.read_response(self.prompt)

    def get_pid_of(self, service):
        cmd_output = self.send_command("ps -A | grep " + service)
        pid = re.search(r'\d+ .*' + service, cmd_output)
        return pid.group().split()[0] if pid else None


def run_gdb(gdb_path, command_file):
    print "Starting gdb..."
    try:
        subprocess.call([gdb_path, "--command=" + command_file])
    except Exception as exception:
        subprocess.call("reset")
        print_failure("Debugging session ended in an error: " + exception.message)


def get_service_pid(config):
    service = extract_service_name(config.program_path)
    telnet = TelnetConnection(ip=config.target_ip, user=config.target_user, password=config.target_password,
                              prompt=config.target_prompt)
    pid = telnet.get_pid_of(service)

    if pid:
        print_success('pid of ' + service + ' = ' + pid)
    else:
        print_failure('pid of ' + service + ' not found')

    return pid


def extract_service_name(service_path):
    filename = os.path.split(service_path)[1]
    return os.path.splitext(filename)[0]


def generate_gdb_command_file(config):
    print_info("Generating gdb command file...")

    cmd_file = open(config.command_file, 'w')
    cmd_file.write('set solib-search-path ' + config.solib_search_path + '\n')
    cmd_file.write('set auto-solib-add on\n')
    cmd_file.write('dir ' + config.source_search_path + '\n')

    if config.core_path:
        cmd_file.write('core-file ' + config.core_path + '\n')
    else:
        if config.is_qnx_target:
            cmd_file.write('target qnx ' + config.target_ip + ':' + config.target_debug_port + '\n')
        else:
            cmd_file.write('target extended-remote ' + config.target_ip + ':' + config.target_debug_port + '\n')

        if config.program_path:
            cmd_file.write('file ' + config.program_path + '\n')
            pid = get_service_pid(config)
            if pid:
                cmd_file.write('attach ' + pid + '\n')

    if config.breakpoint_file:
        cmd_file.write("source " + config.breakpoint_file + '\n')

    cmd_file.close()
    print_success('Generated command file successfully! (' + cmd_file.name + ')')


def parse_args():
    parser = argparse.ArgumentParser(
        description='GDB Developer Tool: developer script to quickly and easily debug a remote target or core file.')
    parser.add_argument(
        '-p',
        '--program',
        type=str,
        help="Relative or absolute path to program executable (ends in *.full or *.debug)")
    parser.add_argument(
        '-c',
        '--core',
        type=str,
        help="Relative or absolute path to core file")
    parser.add_argument(
        '-b',
        '--breakpoints',
        type=str,
        help="Relative or absolute path to breakpoint/watchpoint file")
    parser.add_argument(
        '-cm',
        '--command',
        type=str,
        help="Relative or absolute path to command file (this script will generate its own if not provided)")
    parser.add_argument(
        '-ot',
        '--other-target',
        action='store_true',
        default=False,
        help="Use when the remote target is run on a non-QNX OS")
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    config = Config(args)

    if config.generate_command_file:
        generate_gdb_command_file(config)

    run_gdb(config.gdb_path, config.command_file)
    print 'GDT Session ended'


if __name__ == '__main__':
    main()
