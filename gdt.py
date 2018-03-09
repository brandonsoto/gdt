#!/usr/bin/python

import argparse
import json
import os
import re
from multiprocessing.pool import ThreadPool
import socket
import subprocess
import telnetlib

GDT_DIR = os.path.dirname(os.path.abspath(__file__))


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


class Target:
    def __init__(self, ip, user, password, port, prompt):
        self.ip = ip
        self.user = user
        self.password = password
        self.port = port
        self.prompt = prompt

    def full_address(self):
        return self.ip + ":" + self.port


class GDB_Option:
    def __init__(self, name, value, enabled):
        self.name = name
        self.value = value
        self.enabled = enabled



class Config:
    def __init__(self, args):
        data = json.load(open(os.path.join(GDT_DIR, 'gdt_config.json')))

        self.is_qnx_target = not args.other_target
        self.symbol_paths = data["symbol_paths"]
        self.generate_command_file = not args.command
        self.command_file = args.command if args.command else os.path.join(GDT_DIR, "gdb_commands.txt")
        self.target = Target(data["target_ip"], data["target_user"], data["target_password"], data["target_debug_port"], data["target_prompt"])
        self.gdb_path = data["gdb_path"]
        self.project_path = data["project_root"]
        self.excluded_dirs = data["excluded_dirs"]
        self.solib_separator = ";"
        self.source_separator = ";" if self.is_qnx_target else ":"
        self.core_path = args.core if args.core else ""
        self.program_path = args.program if args.program else ""
        self.breakpoint_file = args.breakpoints if args.breakpoints else ""
        self.opts = {
            "pagination": GDB_Option('set pagination', "off", True),
            "auto_solib": GDB_Option('set auto-solib-add', "on", True),
            "solib_path": GDB_Option('set solib-search-path', "", False),
            "source_path" : GDB_Option('dir', "", False),
            "core_file": GDB_Option('core-file', "", args.core is not None),
            "qnx_target": GDB_Option('target qnx', self.target.full_address(), self.is_qnx_target),
            "target": GDB_Option('target extended-remote', self.target.full_address(), not self.is_qnx_target),
            "program": GDB_Option('file', args.program, args.program is not None),
            "pid": GDB_Option('attach', "", args.program is not None and args.core is None),
            "breakpoint": GDB_Option('source', args.breakpoints, args.breakpoints is not None)
        }

        self.validate()
        self.init_paths()

    def validate(self):
        print 'Validating configuration...'
        self.validate_args()
        self.validate_files()
        self.validate_dirs()
        self.validate_target()
        print 'Validated configuration successfully!'

    def validate_args(self):
        # TODO: need to implement
        pass

    def validate_dirs(self):
        for dir_path in self.symbol_paths + [self.project_path]:
            verify_dir_exists(dir_path)

    def validate_files(self):
        for file_path in [self.program_path, self.core_path, self.gdb_path, self.command_file if not self.generate_command_file else None, self.breakpoint_file]:
            verify_file_exists(file_path)

    def validate_target(self):
        ip = re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.target.ip)
        if not ip:
            raise Exception('invalid target IPv4 address - "' + self.target.ip + '"')

        port = re.search(r"^\d+$", self.target.port)
        if not port:
            raise Exception('invalid target debug port - "' + self.target.port + '"')

    def init_search_paths(self):
        threadpool = ThreadPool(processes=len(self.symbol_paths) + 1)
        paths = [threadpool.apply_async(generate_search_path, (path, self.excluded_dirs, is_shared_library, self.solib_separator)) for path in self.symbol_paths]
        paths.append(threadpool.apply_async(generate_search_path, (self.project_path, self.excluded_dirs, is_cpp_file, self.source_separator)))
        self.opts["solib_path"].value = self.solib_separator.join([path.get() for path in paths[:-1]])
        self.opts["solib_path"].enabled = True
        self.opts["source_path"].value = paths[-1].get()
        self.opts["source_path"].enabled = True


    def init_paths(self):
        print 'Initializing paths...'

        self.project_path = get_str_repr(os.path.abspath(self.project_path))
        self.gdb_path = os.path.abspath(self.gdb_path)
        self.opts["program"].value = get_str_repr(os.path.abspath(self.program_path))
        self.opts["core_file"].value = get_str_repr(os.path.abspath(self.core_path))
        self.opts["breakpoint"].value = get_str_repr(os.path.abspath(self.breakpoint_file))

        if self.generate_command_file:
            self.init_search_paths()
            if not self.core_path:
                self.opts["pid"].value = get_service_pid(self)
                self.opts["pid"].enabled = True

        print 'Initialized paths successfully!'


# thanks to Blayne Dennis for this class
class TelnetConnection:
    def __init__(self, target):
        self.TIMEOUT_SEC = 10
        self.PORT = 23
        self.target = target
        self.prompt = target.prompt
        self.session = None
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
            self.session = telnetlib.Telnet(self.target.ip, self.PORT, self.TIMEOUT_SEC)
        except (socket.timeout, socket.error):
            raise Exception("Telnet: Server doesn't respond")

        self.read_response('login: ')
        self.session.write('{}\n'.format(self.target.user))
        self.read_response('Password: ')
        self.session.write('{}\n'.format(self.target.password))
        resp = self.read_response(self.prompt)
        if resp[-len(self.prompt):] != self.prompt:
            raise Exception('Telnet: Username or password invalid')

    def send_command(self, cmd):
        self.session.write('{}\n'.format(cmd))
        return self.read_response(self.prompt)

    def get_pid_of(self, service):
        cmd_output = self.send_command("ps -A | grep " + service)
        match = re.search(r'\d+ .*' + service, cmd_output)
        pid = match.group().split()[0] if match else None
        print 'pid of ' + service + ' = ' + pid
        return pid


def run_gdb(gdb_path, command_file):
    print "Starting gdb..."
    try:
        subprocess.call([gdb_path, "--command=" + command_file])
    except Exception as exception:
        subprocess.call("reset")
        print "Debugging session ended in an error: " + exception.message


def get_service_pid(config):
    service = extract_service_name(config.program_path)
    telnet = TelnetConnection(config.target)
    return telnet.get_pid_of(service)


def extract_service_name(service_path):
    filename = os.path.split(service_path)[1]
    return os.path.splitext(filename)[0]


def generate_gdb_command_file(config):
    print "Generating gdb command file..."

    cmd_file = open(config.command_file, 'w')
    for key, option in config.opts.iteritems():
        if option.enabled:
            cmd_file.write(option.name + " " + option.value + "\n")
    cmd_file.close()

    print 'Generated command file successfully! (' + cmd_file.name + ')'


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
        help="Relative or absolute path to command file. This arg cannot be used with any other arg. (This script will generate its own if not provided)")
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

    #run_gdb(config.gdb_path, config.command_file)
    print 'GDT Session ended'


if __name__ == '__main__':
    main()
