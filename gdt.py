#!/usr/bin/python

import argparse
import json
import os
import re
import socket
import subprocess
import telnetlib


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
    paths = []
    for root, dirs, files in os.walk(root_path, topdown=True):
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        if any(unary_func(f) for f in files):
            paths.append(get_str_repr(os.path.abspath(root)))
    return separator.join(paths)


def generate_solib_search_path(root_path, excluded_dirs):
    return generate_search_path(root_path, excluded_dirs, is_shared_library, ";")


def generate_source_search_path(root_path, excluded_dirs):
    return generate_search_path(root_path, excluded_dirs, is_cpp_file, ";")


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
        print "Loading configuration..."
        data = json.load(open('gdt_config.json'))

        self.module_path = args.module
        self.core_path = args.core
        self.is_qnx_target = not args.other_target
        self.symbols_path = data["symbols_path"]
        self.generate_command_file = not args.commands
        self.command_file = args.commands if args.commands else os.path.join(os.path.dirname(os.path.abspath(__file__)), "gdb_commands.txt")
        self.target_ip = data["target_ip"]
        self.target_user = data["target_user"]
        self.target_password = data["target_password"]
        self.target_debug_port = data["target_debug_port"]
        self.target_prompt = data["target_prompt"]
        self.gdb_path = data["gdb_path"]
        self.project_path = data["project_path"]
        self.solib_search_path = ""
        self.source_search_path = ""
        self.excluded_dirs = data["excluded_dirs"]

        self.validate()
        self.init_paths()

    def validate(self):
        print "Validating configuration..."

        for file_path in [self.module_path, self.core_path, self.gdb_path, self.command_file if not self.generate_command_file else None]:
            verify_file_exists(file_path)

        for dir_path in [self.symbols_path, self.project_path]:
            verify_dir_exists(dir_path)

    def init_paths(self):
        print "Generating search paths..."

        self.solib_search_path = generate_solib_search_path(self.symbols_path, self.excluded_dirs)
        # self.source_search_path = generate_source_search_path(self.project_path, self.excluded_dirs)
        self.project_path = get_str_repr(os.path.abspath(self.project_path))
        self.gdb_path = os.path.abspath(self.gdb_path)

        if self.module_path:
            self.module_path = get_str_repr(os.path.abspath(self.module_path))

        if self.core_path:
            self.core_path = get_str_repr(os.path.abspath(self.core_path))


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
        self.read_response('Password:')
        self.session.write('{}\n'.format(self.password))
        resp = self.read_response(self.prompt)
        if resp[-len(self.prompt):] != self.prompt:
            raise Exception('Telnet: Username or password invalid')

    def send_command(self, cmd):
        self.session.write('{}\n'.format(cmd))
        return self.read_response(self.prompt)

    def get_pid_of(self, service):
        print "Getting pid of " + service + "..."
        cmd_output = self.send_command("ps -A | grep " + service)
        output_lines = cmd_output.splitlines()

        pid = None
        for line in output_lines:
            pid = re.search(r'\d+ ?', line)
            if pid:
                pid = pid.group()
                break

        if pid:
            print "pid of " + service + " = " + pid

        return pid


def run_gdb(gdb_path, command_file):
    print "Starting gdb..."
    try:
        subprocess.call([gdb_path, "--command=" + command_file])
    except Exception as exception:
        subprocess.call("reset")
        print "Debugging session ended in an error: " + exception.message


def get_service_pid(config):
    service = extract_service_name(config.module_path)
    telnet = TelnetConnection(ip=config.target_ip, user=config.target_user, password=config.target_password,
                              prompt=config.target_prompt)
    return telnet.get_pid_of(service)


def extract_service_name(service_path):
    filename = os.path.split(service_path)[1]
    return os.path.splitext(filename)[0]


def generate_gdb_command_file(config):
    print "Generating gdb command file..."

    cmd_file = open(config.command_file, 'w')
    cmd_file.write('set solib-search-path ' + config.solib_search_path + '\n')
    cmd_file.write('set auto-solib-add on\n')
    cmd_file.write('dir ' + config.project_path + '\n')

    if config.core_path:
        cmd_file.write('core-file ' + config.core_path + '\n')
    else:
        if config.is_qnx_target:
            cmd_file.write('target qnx ' + config.target_ip + ':' + config.target_debug_port + '\n')
        else:
            cmd_file.write('target extended-remote ' + config.target_ip + ':' + config.target_debug_port + '\n')

        if config.module_path:
            cmd_file.write('file ' + config.module_path + '\n')
            pid = get_service_pid(config)
            if pid:
                cmd_file.write('attach ' + pid + '\n')
    cmd_file.close()


def parse_args():
    parser = argparse.ArgumentParser(
        description='GDB Developer Tool: developer script to quickly and easily debug a remote target or core file.')
    parser.add_argument(
        '-m',
        '--module',
        type=str,
        help="Relative or absolute path to module executable (ends in *.full or *.debug)")
    parser.add_argument(
        '-c',
        '--core',
        type=str,
        help="Relative or absolute path to core file")
    parser.add_argument(
        '-cm',
        '--commands',
        type=str,
        help="Relative or absolute path to GDB command file (this script will generate its own if not provided)")
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


if __name__ == '__main__':
    main()
