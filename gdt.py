#!/usr/bin/python

import argparse
import json
import os
import re
from multiprocessing.pool import ThreadPool
import socket
import subprocess
import telnetlib

SUCCESS_COLOR = '\033[92m'
FAIL_COLOR = '\033[91m'
END_COLOR = '\033[0m'
GDT_DIR = os.path.dirname(os.path.abspath(__file__))


def print_success(string):
    print SUCCESS_COLOR + string + END_COLOR


def print_failure(string):
    print FAIL_COLOR + string + END_COLOR


def get_str_repr(string):
    return repr(str(string))[1:-1]


def verify_path_exists(path, path_exists):
    if path and not path_exists(path):
        raise Exception('path does not exist - "' + path + '"')


def verify_dir_exists(path):
    verify_path_exists(path, os.path.isdir)


def verify_file_exists(path):
    verify_path_exists(path, os.path.isfile)


def generate_search_path(root_path, excluded_dirs, unary_func, separator):
    search_path = []
    for root, dirs, files in os.walk(root_path, topdown=True):
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        if any(unary_func(f) for f in files):
            search_path.insert(0, get_str_repr(root))
    return separator.join(search_path)


def is_shared_library(path):
    file_extension = ".so"
    lib_number = re.search(r'\d+$', path)
    if lib_number:
        file_extension += "." + lib_number.group()
    return path.endswith(file_extension)


def is_cpp_file(path):
    return any(path.endswith(extension) for extension in [".cpp", ".c", ".cc", ".h", ".hpp"])


class Config:
    def __init__(self, args):
        data = json.load(open(os.path.join(GDT_DIR, 'gdt_config.json')))

        self.program_path = args.program
        self.core_path = args.core
        self.is_qnx_target = not args.other_target
        self.symbol_paths = data["symbol_paths"]
        self.generate_command_file = not args.command
        self.command_file = args.command if args.command else os.path.join(GDT_DIR, "gdb_commands.txt")
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
        self.solib_separator = ";"
        self.source_separator = ";" if self.is_qnx_target else ":"

        self.validate()
        self.init_paths()

    def validate(self):
        print 'Validating configuration...'
        self.validate_files()
        self.validate_dirs()
        self.validate_target()
        print_success('Validated configuration successfully!')

    def validate_dirs(self):
        for dir_path in self.symbol_paths + [self.project_path]:
            verify_dir_exists(dir_path)

    def validate_files(self):
        for file_path in [self.program_path, self.core_path, self.gdb_path, self.command_file if not self.generate_command_file else None, self.breakpoint_file]:
            verify_file_exists(file_path)

    def validate_target(self):
        ip = re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.target_ip)
        if not ip:
            raise Exception('invalid target IPv4 address - "' + self.target_ip + '"')

        port = re.search(r"^\d+$", self.target_debug_port)
        if not port:
            raise Exception('invalid target debug port - "' + self.target_debug_port + '"')

    def init_search_paths(self):
        threadpool = ThreadPool(processes=len(self.symbol_paths) + 1)
        paths = [threadpool.apply_async(generate_search_path, (path, self.excluded_dirs, is_shared_library, self.solib_separator)) for path in self.symbol_paths]
        paths.append(threadpool.apply_async(generate_search_path, (self.project_path, self.excluded_dirs, is_cpp_file, self.source_separator)))
        self.solib_search_path = self.solib_separator.join([path.get() for path in paths[:-1]])
        self.source_search_path = paths[-1].get()


    def init_paths(self):
        print 'Initializing paths...'

        if self.program_path:
            self.program_path = get_str_repr(os.path.abspath(self.program_path))

        if self.core_path:
            self.core_path = get_str_repr(os.path.abspath(self.core_path))

        if self.breakpoint_file:
            self.breakpoint_file = get_str_repr(os.path.abspath(self.breakpoint_file))

        if self.generate_command_file:
            self.init_search_paths()

        self.project_path = get_str_repr(os.path.abspath(self.project_path))
        self.gdb_path = os.path.abspath(self.gdb_path)

        print_success('Initialized paths successfully!')


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
    print "Generating gdb command file..."
    has_core_file = config.core_path is not None
    has_program_path = config.program_path is not None
    ip_addr = config.target_ip + ":" + config.target_debug_port
    pid = get_service_pid(config) if not has_core_file and has_program_path else None

    options = [
        {"name": "set pagination", "value": "off", "enabled": True},
        {"name": "set solib-search-path", "value": config.solib_search_path, "enabled": True},
        {"name": "set auto-solib-add", "value": "on", "enabled": True},
        {"name": "dir", "value": config.source_search_path, "enabled": True},
        {"name": "core-file", "value": config.core_path, "enabled": has_core_file},
        {"name": "target qnx", "value": ip_addr, "enabled": not has_core_file and config.is_qnx_target},
        {"name": "target extended-remote", "value": ip_addr, "enabled": not has_core_file and not config.is_qnx_target},
        {"name": "file", "value": config.program_path, "enabled": has_program_path},
        {"name": "attach", "value": pid, "enabled": not has_core_file and has_program_path and pid is not None},
        {"name": "source", "value": config.breakpoint_file, "enabled": bool(config.breakpoint_file)}
    ]

    cmd_file = open(config.command_file, 'w')
    for option in options:
        if option["enabled"]:
            cmd_file.write(option["name"] + " " + option["value"] + "\n")
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
