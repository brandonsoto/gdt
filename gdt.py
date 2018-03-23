#!/usr/bin/python

from collections import OrderedDict
from multiprocessing.pool import ThreadPool
import argparse
import json
import os
import re
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


def extract_service_name(service_path):
    filename = os.path.split(service_path)[1]
    return os.path.splitext(filename)[0]


def create_command_file(config):
    print "Generating command file..."
    cmd_file = open(config.command_file, 'w')
    for key, option in config.opts.iteritems():
        if option.enabled:
            cmd_file.write(option.prefix + " " + option.value + "\n")
    cmd_file.close()
    print 'Generated command file successfully! (' + cmd_file.name + ')'


class Target:
    def __init__(self, ip, user, password, port, prompt):
        self.ip = ip
        self.user = user
        self.password = password
        self.port = port
        self.prompt = prompt

    def full_address(self):
        return self.ip + ":" + self.port

    def ssh_address(self):
        return self.user + "@" + self.ip


class DebugOption:
    def __init__(self, prefix, value, enabled):
        self.prefix = prefix
        self.value = value
        self.enabled = enabled


class CommonConfig:
    def __init__(self):
        self.json_data = json.load(open(os.path.join(GDT_DIR, 'gdt_config.json')))
        self.project_path = get_str_repr(os.path.abspath(self.json_data["project_root"]))
        self.gdb_path = os.path.abspath(self.json_data["gdb_path"])
        self.excluded_dirs = self.json_data["excluded_dirs"]
        self.solib_separator = ";"

        self.validate()

    def validate(self):
        verify_file_exists(self.gdb_path)
        verify_dir_exists(self.project_path)


class GeneratedConfig(CommonConfig):
    def __init__(self, args):
        CommonConfig.__init__(self)
        self.command_file = os.path.join(GDT_DIR, "gdb_commands.txt")
        self.symbol_paths = args.symbols.name if args.symbols else self.json_data["symbol_paths"]
        self.opts = OrderedDict([
            ("pagination", DebugOption('set pagination', "off", True)),
            ("auto_solib", DebugOption('set auto-solib-add', "on", True)),
            ("solib_path", DebugOption('set solib-search-path', "", True)),
            ("program", DebugOption('file', get_str_repr(os.path.abspath(args.program.name)), True)),
        ])
        for dir_path in self.symbol_paths:
            verify_dir_exists(dir_path)


class CoreConfig(GeneratedConfig):
    def __init__(self, args):
        GeneratedConfig.__init__(self, args)
        self.opts["core"] = DebugOption('core', get_str_repr(os.path.abspath(args.core.name)), True)
        self.init_search_paths()
        create_command_file(self)

    def init_search_paths(self):
        print "Generating search paths..."
        max_threads = len(self.symbol_paths)
        threadpool = ThreadPool(processes=max_threads)
        paths = [threadpool.apply_async(generate_search_path, (path, self.excluded_dirs, is_shared_library, self.solib_separator)) for path in self.symbol_paths]
        self.opts["solib_path"].value = self.solib_separator.join([path.get() for path in paths[:-1]])
        # threadpool.close()  # TODO(brandon): check this on Windows
        print "Generated search paths successfully!"


class RemoteConfig(GeneratedConfig):
    def __init__(self, args):
        GeneratedConfig.__init__(self, args)
        self.is_qnx_target = not args.other_target
        self.target = Target(self.json_data["target_ip"], self.json_data["target_user"], self.json_data["target_password"], self.json_data["target_debug_port"], self.json_data["target_prompt"])
        self.source_separator = ";" if self.is_qnx_target else ":"
        self.use_ssh = args.ssh

        self.validate_target()
        self.init_options(args)
        create_command_file(self)

    def validate_target(self):
        ip = re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.target.ip)
        if not ip:
            raise Exception('invalid target IPv4 address - "' + self.target.ip + '"')

        port = re.search(r"^\d+$", self.target.port)
        if not port:
            raise Exception('invalid target debug port - "' + self.target.port + '"')

    def init_options(self, args):
        self.opts["target"] = DebugOption('target qnx' if self.is_qnx_target else 'target extended-remote', self.target.full_address(), True)
        self.opts["source_path"] = DebugOption('dir', "", True)
        self.opts["pid"] = DebugOption('attach', "", True)
        self.opts["breakpoint"] = DebugOption('source', get_str_repr(os.path.abspath(args.breakpoints.name)) if args.breakpoints else None, bool(args.breakpoints))
        self.init_search_paths()
        self.init_pid()

    def init_search_paths(self):
        print "Generating search paths..."
        max_threads = len(self.symbol_paths) + 1
        threadpool = ThreadPool(processes=max_threads)
        paths = [threadpool.apply_async(generate_search_path, (path, self.excluded_dirs, is_shared_library, self.solib_separator)) for path in self.symbol_paths]
        paths.append(threadpool.apply_async(generate_search_path, (self.project_path, self.excluded_dirs, is_cpp_file, self.source_separator)))
        self.opts["solib_path"].value = self.solib_separator.join([path.get() for path in paths[:-1]])
        self.opts["source_path"].value = paths[-1].get()
        # threadpool.close()  # TODO(brandon): check this on Windows
        print "Generated search paths successfully!"

    def init_pid(self):
        service_name = extract_service_name(self.opts['program'].value)
        print 'Getting pid of ' + service_name + '...'
        output = self.ssh_pid(service_name) if self.use_ssh else self.telnet_pid(service_name)
        match = re.search(r'\d+ .*' + service_name, output)
        pid = match.group().split()[0] if match else None
        self.opts["pid"].value = pid
        self.opts["pid"].enabled = pid is not None
        print 'pid of ' + service_name + ' = ' + str(pid)

    def telnet_pid(self, service_name):
        telnet = TelnetConnection(self.target)
        return telnet.get_pid_of(service_name)

    def ssh_pid(self, service_name):
        ssh_command = 'ssh ' + self.target.ssh_address() + ' "ps -A | grep ' + service_name + '"'
        return subprocess.Popen(ssh_command, stdout=subprocess.PIPE, shell=True).stdout.read()


class CommandConfig(CommonConfig):
    def __init__(self, args):
        CommonConfig.__init__(self)
        self.command_file = args.input.name


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
        return self.send_command("ps -A | grep " + service)


def run_gdb(gdb_path, command_file):
    print "Starting gdb..."
    try:
        subprocess.call([gdb_path, "--command=" + command_file])
    except Exception as exception:
        subprocess.call("reset")
        print "Debugging session ended in an error: " + exception.message


def init_args():
    parser = argparse.ArgumentParser(description='GDB Developer Tool: developer script to quickly and easily debug a remote target or core file.')
    subparsers = parser.add_subparsers()

    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('program', type=argparse.FileType(), help='Path to program (usually ends in .full or .debug)')
    common_parser.add_argument('-s', '--symbols', type=str, nargs="+", help='Path to command file')

    core_parser = subparsers.add_parser('core', help='Use when debugging a core file', parents=[common_parser])
    core_parser.add_argument('-c', '--core', required=True, type=argparse.FileType(), help='Path to core file')
    core_parser.set_defaults(func=lambda args: CoreConfig(args))

    remote_parser = subparsers.add_parser('remote', help='Use when debugging a remote program', parents=[common_parser])
    remote_parser.add_argument('-b', '--breakpoints', type=argparse.FileType(), help='Path to breakpoint file')
    remote_parser.add_argument('-ot', '--other-target', action='store_true', default=False, help="Use when the remote target is run on a non-QNX OS")
    remote_parser.add_argument('--ssh', action='store_true', default=False, help="Use ssh instead of telnet to retrieve pid")
    remote_parser.set_defaults(func=lambda args: RemoteConfig(args))

    cmd_parser = subparsers.add_parser('cmd', help='Use to run gdb with a command file')
    cmd_parser.add_argument('input', type=argparse.FileType(), help='Path to command file')
    cmd_parser.set_defaults(func=lambda args: CommandConfig(args))

    return parser.parse_args()


def close_files(args):
    for arg in vars(args).iteritems():
        if type(arg[1]) == file:
            arg[1].close()


def parse_args():
    args = init_args()
    close_files(args)
    return args


def main():
    args = parse_args()
    config = args.func(args)
    run_gdb(config.gdb_path, config.command_file)
    print 'GDT Session ended'


if __name__ == '__main__':
    main()
