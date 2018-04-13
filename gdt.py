#!/usr/bin/python

from collections import OrderedDict
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


def generate_search_path(root_path, excluded_dir_names, unary_func, separator):
    search_path = []
    for root, dirs, files in os.walk(root_path, topdown=True):
        dirs[:] = [d for d in dirs if d not in excluded_dir_names]
        if any(unary_func(f) for f in files):
            search_path.insert(0, get_str_repr(os.path.abspath(root)))
    return separator.join(search_path)


def is_shared_library(path):
    file_extension = ".so"
    lib_number = re.search(r'\d+$', path)
    if lib_number:
        file_extension += "." + lib_number.group()
    return path.endswith(file_extension)


def is_cpp_file(path):
    return any(path.endswith(extension) for extension in [".cpp", ".c", ".cc", ".h", ".hpp"])


def extract_program_name(service_path):
    filename = os.path.split(service_path)[1]
    return os.path.splitext(filename)[0]


class Target:
    def __init__(self, ip, user, password, port, prompt):
        self.ip = ip
        self.user = user
        self.password = password
        self.port = port
        self.prompt = prompt

    def full_address(self):
        return self.ip + ":" + self.port


class DebugOption:
    def __init__(self, prefix, value):
        self.prefix = prefix
        self.value = value


class CommonConfig:
    def __init__(self):
        self.json_data = json.load(open(os.path.join(GDT_DIR, 'gdt_files', 'gdt_config.json')))
        self.project_path = get_str_repr(os.path.abspath(self.json_data["project_root_path"]))
        self.gdb_path = os.path.abspath(self.json_data["gdb_path"])
        self.excluded_dir_names = self.json_data["excluded_dir_names"]
        self.solib_separator = ";"

        self.validate()

    def validate(self):
        verify_file_exists(self.gdb_path)
        verify_dir_exists(self.project_path)


class GeneratedConfig(CommonConfig):
    def __init__(self, args):
        CommonConfig.__init__(self)
        self.command_file = os.path.join(os.getcwd(), "gdb_commands.txt")
        self.symbol_root_paths = args.symbols if args.symbols else self.json_data["symbol_root_paths"]
        self.source_separator = ";"
        self.opts = OrderedDict([("pagination", DebugOption('set pagination', "off")),
                                 ("auto_solib", DebugOption('set auto-solib-add', "on")),
                                 ("program", DebugOption('file', get_str_repr(os.path.abspath(args.program.name))))])
        for dir_path in self.symbol_root_paths:
            verify_dir_exists(dir_path)

    def init_search_paths(self):
        print "Generating search paths..."
        solib_search_paths = [generate_search_path(path, self.excluded_dir_names, is_shared_library, self.solib_separator) for path in self.symbol_root_paths]
        self.add_option('solib_path', DebugOption('set solib-search-path', self.solib_separator.join(path for path in solib_search_paths)))
        self.add_option('source_path', DebugOption('dir', generate_search_path(self.project_path, self.excluded_dir_names, is_cpp_file, self.source_separator)))
        print "Generated search paths successfully!"

    def create_command_file(self):
        print "Generating command file..."
        with open(self.command_file, 'w') as cmd_file:
            for key, option in self.opts.iteritems():
                cmd_file.write(option.prefix + " " + option.value + "\n")
        print 'Generated command file successfully! (' + cmd_file.name + ')'

    def add_option(self, key, option):
        self.opts[key] = option


class CoreConfig(GeneratedConfig):
    def __init__(self, args):
        GeneratedConfig.__init__(self, args)
        self.init_search_paths()
        self.add_option('core', DebugOption('core-file', get_str_repr(os.path.abspath(args.core.name))))
        self.create_command_file()


class RemoteConfig(GeneratedConfig):
    def __init__(self, args):
        GeneratedConfig.__init__(self, args)
        self.is_qnx_target = not args.other_target
        self.target = Target(self.json_data["target_ip"], self.json_data["target_user"], self.json_data["target_password"], self.json_data["target_debug_port"], self.json_data["target_prompt"])
        self.source_separator = ";" if self.is_qnx_target else ":"
        self.telnet = TelnetConnection(self.target)

        self.validate_target()
        self.init_options(args)
        self.init_search_paths()
        self.init_pid()
        self.create_command_file()

    def validate_target(self):
        ip = re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.target.ip)
        if not ip:
            raise Exception('invalid target IPv4 address - "' + self.target.ip + '"')

        port = re.search(r"^\d+$", self.target.port)
        if not port:
            raise Exception('invalid target debug port - "' + self.target.port + '"')

    def init_options(self, args):
        self.add_option('target', DebugOption('target qnx' if self.is_qnx_target else 'target extended-remote', self.target.full_address()))

        if args.breakpoints:
            self.add_option('breakpoint', DebugOption('source', get_str_repr(os.path.abspath(args.breakpoints.name))))

    def init_pid(self):
        service_name = extract_program_name(self.opts['program'].value)
        print 'Getting pid of ' + service_name + '...'
        pid = self.telnet_pid(service_name)
        print 'pid of ' + service_name + ' = ' + str(pid)

        if pid:
            self.add_option('pid', DebugOption('attach', pid))

    def telnet_pid(self, service_name):
        output = self.telnet.get_pid_of(service_name)
        match = re.search(r'\d+ .*' + service_name, output)
        return match.group().split()[0] if match else None


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
        self.read_response('Password:')
        self.session.write('{}\n'.format(self.target.password))
        resp = self.read_response(self.prompt)
        if resp[-len(self.prompt):] != self.prompt:
            raise Exception('Telnet: Username or password invalid')

    def send_command(self, cmd):
        self.session.write('{}\n'.format(cmd))
        return self.read_response(self.prompt)

    def get_pid_of(self, service):
        return self.send_command("ps -A | grep " + service)

    def get_shared_dependencies(self, program_name):
        return self.send_command('find . -name "' + program_name + '" -exec ldd {} \;')


def run_gdb(gdb_path, command_file):
    print "Starting gdb..."
    returncode = None
    process = None
    try:
        process = subprocess.Popen(args=[gdb_path, '--command=' + command_file])
        while returncode is None:
            try:
                returncode = process.wait()
            except KeyboardInterrupt:
                continue  # ignore interrupt to allow GDB child process to handle it
    except OSError as error:
        print "GDT encountered an error: " + error.message
    finally:
        if process is not None and returncode is None:
            process.kill()


def close_files(args):
    for arg in vars(args).iteritems():
        if type(arg[1]) == file:
            arg[1].close()


def parse_args():
    parser = argparse.ArgumentParser(description='GDB Developer Tool: developer script to quickly and easily debug a remote target or core file.')
    subparsers = parser.add_subparsers()

    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('-p', '--program', required=True, type=argparse.FileType(), help='Path to program exectuable (usually ends in .full)')
    common_parser.add_argument('-s', '--symbols', type=str, nargs="+", help='List of symbol directories')

    core_parser = subparsers.add_parser('core', help='Use when debugging a core file', parents=[common_parser])
    core_parser.add_argument('-c', '--core', required=True, type=argparse.FileType(), help='Path to core file')
    core_parser.set_defaults(func=lambda args: CoreConfig(args))

    remote_parser = subparsers.add_parser('remote', help='Use when debugging a remote program', parents=[common_parser])
    remote_parser.add_argument('-b', '--breakpoints', type=argparse.FileType(), help='Path to breakpoint file')
    remote_parser.add_argument('-ot', '--other-target', action='store_true', default=False, help="Use when the remote target is run on a non-QNX OS")
    remote_parser.set_defaults(func=lambda args: RemoteConfig(args))

    cmd_parser = subparsers.add_parser('cmd', help='Use to run gdb with a command file')
    cmd_parser.add_argument('input', type=argparse.FileType(), help='Path to command file')
    cmd_parser.set_defaults(func=lambda args: CommandConfig(args))

    args = parser.parse_args()
    close_files(args)
    return args


def main():
    args = parse_args()
    config = args.func(args)
    run_gdb(config.gdb_path, config.command_file)
    print 'GDT Session ended'


if __name__ == '__main__':
    main()
