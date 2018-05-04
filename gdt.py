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
GDT_CONFIG_DIR = os.path.join(GDT_DIR, 'gdt_files')
GDT_CONFIG_FILE = os.path.join(GDT_CONFIG_DIR, 'config.json')
GDB_COMMANDS_FILE = os.path.join(GDT_CONFIG_DIR, 'commands.txt')
GDBINIT_FILE = os.path.join(GDT_CONFIG_DIR, 'gdbinit')
DEFAULT_GDBINIT_FILE = os.path.join(GDT_CONFIG_DIR, 'default_gdbinit')
DEFAULT_IP = "192.168.33.42"
DEFAULT_USER = "vagrant"
DEFAULT_PASSWORD = "vagrant"
DEFAULT_DEBUG_PORT = "8000"
DEFAULT_PROMPT = "# "
IPV4_REGEX = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
PORT_REGEX = r"^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
SHARED_LIB_REGEX = r'\.so(\.\d+)?$'


def get_str_repr(string):
    return repr(str(string))[1:-1]


def verify_path_exists(path, path_exists):
    if path and not path_exists(path):
        raise Exception('path does not exist - "' + path + '"')


def verify_dir_exists(path):
    verify_path_exists(path, os.path.isdir)


def verify_file_exists(path):
    verify_path_exists(path, os.path.isfile)


def validate_ipv4_address(ip):
    ip_match = re.search(IPV4_REGEX, ip)
    return ip_match.group() if ip_match else None


def validate_port(port):
    port_match = re.search(PORT_REGEX, port)
    return port_match.group() if port_match else None


def validate_dir(directory):
    return os.path.abspath(directory) if os.path.isdir(directory) else None


def is_shared_library(path):
    return re.search(SHARED_LIB_REGEX, path) is not None

def is_cpp_file(path):
    return any(path.endswith(extension) for extension in (".cpp", ".c", ".cc", ".h", ".hpp"))


def extract_program_name(program_path):
    filename = os.path.split(program_path)[1]
    return os.path.splitext(filename)[0]


class Target:
    def __init__(self, ip, user, password, port):
        self.ip = ip
        self.user = user
        self.password = password
        self.port = port
        self.validate()

    def full_address(self):
        return self.ip + ":" + self.port

    def validate(self):
        ip = validate_ipv4_address(self.ip)
        if not ip:
            raise Exception('invalid target IPv4 address - "' + self.ip + '"')

        port = validate_port(self.port)
        if not port:
            raise Exception('invalid target debug port - "' + self.port + '"')


class DebugOption:
    def __init__(self, prefix, value):
        self.prefix = prefix
        self.value = value


class ConfigOption:
    def __init__(self, key, desc="", error_str="", validate_func=None, default_value=None, is_raw_input=True, value=None):
        self.key = key
        self.default_value = default_value
        self.value = value
        self.desc = desc
        self.validate_func = validate_func
        self.error_str = error_str
        self.is_raw_input = is_raw_input

        self.init_desc()
        self.init_value()

    def init_desc(self):
        if self.default_value:
            self.desc = self.desc + ' [Default: "' + self.default_value + '"] -> '
        else:
            self.desc = self.desc + ' -> '

    def init_value(self):
        if self.is_raw_input:
            self.value = raw_input(self.desc).strip('"\'')
            if self.value == "" and self.default_value:
                self.value = self.default_value
            elif self.validate_func:
                self.get_valid_value()

    def get_valid_value(self):
        value = self.validate_func(self.value)
        while not value:
            print '"{}" {} Enter again...'.format(self.value, self.error_str)
            value = raw_input(self.desc).strip('"\'')
            value = self.default_value if (value == "" and self.default_value) else value
            value = self.validate_func(value)
        self.value = value


class CommonConfig:
    def __init__(self, args):
        self.generate_config_dir()
        self.generate_gdbinit()
        self.json_data = None
        self.init_json_data(args.config)
        self.project_path = get_str_repr(os.path.abspath(self.json_data["project_root_path"]))
        self.gdb_path = os.path.abspath(self.json_data["gdb_path"])
        self.excluded_dir_names = self.json_data["excluded_dir_names"]
        self.solib_separator = ";"

        verify_file_exists(self.gdb_path)
        verify_dir_exists(self.project_path)

    def init_json_data(self, config_file):
        print 'Reading gdt configuration...'
        if config_file:
            self.json_data = json.load(open(os.path.abspath(config_file.name)))
        elif os.path.isfile(GDT_CONFIG_FILE):
            self.json_data = json.load(open(GDT_CONFIG_FILE))
        else:
            print 'gdt configuration not found!'
            self.generate_config_file()

    def generate_config_dir(self):
        if not os.path.isdir(GDT_CONFIG_DIR):
            os.makedirs(GDT_CONFIG_DIR)

    def generate_gdbinit(self):
        if not os.path.isfile(GDBINIT_FILE):
            with open(GDBINIT_FILE, 'w') as gdbinit:
                gdbinit.write(open(DEFAULT_GDBINIT_FILE, 'r').read())
                print 'Generated gdbinit successfully! (' + GDBINIT_FILE + ")"

    def generate_config_file(self):
        print 'Generating gdt configuration...'
        options = [ConfigOption('gdb_path', 'GDB path', 'is not a file.', lambda file_path: os.path.abspath(file_path) if os.path.isfile(file_path) else None),
                   ConfigOption('project_root_path', 'Project root path', 'is not a directory.', validate_dir),
                   ConfigOption('symbol_root_path', 'Symbol root path', ' is not a directory.', validate_dir),
                   ConfigOption('target_ip', 'Remote target IP', 'is an invalid IPv4 address.', validate_ipv4_address, DEFAULT_IP),
                   ConfigOption('excluded_dir_names', is_raw_input=False, value=[".svn", ".git"]),
                   ConfigOption('target_user', 'Remote target username', default_value=DEFAULT_USER),
                   ConfigOption('target_password', 'Remote target password', default_value=DEFAULT_PASSWORD),
                   ConfigOption('target_debug_port', 'Remote target debug port', "is an invalid port.", validate_port, DEFAULT_DEBUG_PORT),
                   ConfigOption('target_prompt', 'Remote target prompt', default_value=DEFAULT_PROMPT)]
        option_dict = {option.key: option.value for option in options}
        with open(GDT_CONFIG_FILE, 'w') as config_file:
            json.dump(option_dict, config_file, sort_keys=True, indent=3)
        self.json_data = json.load(open(GDT_CONFIG_FILE, 'r'))
        print 'Generated gdt configuration successfully! (' + GDT_CONFIG_FILE + ')'


class GeneratedConfig(CommonConfig):
    def __init__(self, args):
        CommonConfig.__init__(self, args)
        self.command_file = GDB_COMMANDS_FILE
        self.symbol_root_path = args.symbols if args.symbols else self.json_data["symbol_root_path"]
        self.source_separator = ";"
        self.opts = OrderedDict([("program", DebugOption('file', get_str_repr(os.path.abspath(args.program.name))))])
        self.program_name = extract_program_name(self.opts['program'].value)
        verify_dir_exists(self.symbol_root_path)

    def init_search_paths(self):
        print "Generating search paths..."
        self.add_option('solib_path', DebugOption('set solib-search-path', self.generate_solib_search_path()))
        self.add_option('source_path', DebugOption('dir', self.generate_source_search_path()))
        print "Generated search paths successfully!"

    def generate_solib_search_path(self):
        search_path = []
        for root, dirs, files in os.walk(self.project_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in self.excluded_dir_names]
            if any(is_shared_library(f) for f in files):
                search_path.insert(0, get_str_repr(os.path.abspath(root)))
        return self.solib_separator.join(search_path)

    def generate_source_search_path(self):
        search_path = []
        for root, dirs, files in os.walk(self.project_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in self.excluded_dir_names]
            has_cpp_file = any(is_cpp_file(f) for f in files)
            if has_cpp_file and self.program_name in root:
                search_path.insert(0, get_str_repr(os.path.abspath(root)))
            elif has_cpp_file:
                search_path.append(get_str_repr(os.path.abspath(root)))
        return self.source_separator.join(search_path)

    def generate_command_file(self):
        print "Generating command file..."
        with open(self.command_file, 'w') as cmd_file:
            if os.path.isfile(GDBINIT_FILE):
                cmd_file.write(open(GDBINIT_FILE, 'r').read())
            for key, option in self.opts.iteritems():
                cmd_file.write("\n" + option.prefix + " " + option.value)
        print 'Generated command file successfully! (' + cmd_file.name + ')'

    def add_option(self, key, option):
        self.opts[key] = option


class CoreConfig(GeneratedConfig):
    def __init__(self, args):
        GeneratedConfig.__init__(self, args)
        self.init_search_paths()
        self.add_option('core', DebugOption('core-file', get_str_repr(os.path.abspath(args.core.name))))
        self.generate_command_file()


class RemoteConfig(GeneratedConfig):
    def __init__(self, args):
        GeneratedConfig.__init__(self, args)
        self.is_qnx_target = not args.other_target
        self.target = Target(self.json_data["target_ip"], self.json_data["target_user"], self.json_data["target_password"], self.json_data["target_debug_port"])
        self.source_separator = ";" if self.is_qnx_target else ":"
        self.telnet = TelnetConnection(self.target, self.json_data["target_prompt"])

        self.init_search_paths()
        self.init_target()
        self.init_breakpoints(args.breakpoints)
        self.generate_command_file()

    def init_breakpoints(self, breakpoint_file):
        if breakpoint_file:
            self.add_option('breakpoint', DebugOption('source', get_str_repr(os.path.abspath(breakpoint_file.name))))

    def init_target(self):
        self.add_option('target', DebugOption('target qnx' if self.is_qnx_target else 'target extended-remote', self.target.full_address()))
        self.init_pid()

    def init_pid(self):
        print 'Getting pid of ' + self.program_name + '...'
        output = self.telnet.get_pid_of(self.program_name)
        match = re.search(r'\d+ .*' + self.program_name, output)
        pid = match.group().split()[0] if match else None
        if pid:
            self.add_option('pid', DebugOption('attach', pid))
        print 'pid of ' + self.program_name + ' = ' + str(pid)


class CommandConfig(CommonConfig):
    def __init__(self, args):
        CommonConfig.__init__(self, args)
        self.command_file = args.input.name


# thanks to Blayne Dennis for this class
class TelnetConnection:
    def __init__(self, target, prompt):
        self.PORT = 23
        self.TIMEOUT = 10
        self.session = None
        self.prompt = prompt
        self.target = target
        self.connect()
        self.change_prompt(self.prompt)

    def __del__(self):
        self.close()

    def close(self):
        if self.session is not None:
            self.session.close()

    def read_response(self, prompt):
        return self.session.read_until(prompt, self.TIMEOUT)

    def connect(self):
        print 'Connecting to ' + self.target.ip + ':' + str(self.PORT)
        try:
            self.session = telnetlib.Telnet(self.target.ip, self.PORT, self.TIMEOUT)
        except (socket.timeout, socket.error):
            raise Exception('Telnet: Server doesn\'t respond')

        self.read_response('login: ')
        self.session.write('{}\n'.format(self.target.user))
        self.read_response('Password:')
        self.session.write('{}\n'.format(self.target.password))
        resp = self.read_response(self.prompt)
        if resp[-2:] != self.prompt:
            raise Exception('Telnet: Username or password invalid')

    def change_prompt(self, new_prompt):
        self.prompt = new_prompt
        self.send_command('PS1="{}"'.format(new_prompt))
        self.read_response(self.prompt)

    def send_command(self, cmd):
        self.session.write('{}\n'.format(cmd))
        return self.read_response(self.prompt)

    def get_pid_of(self, service):
        return self.send_command("ps -A | grep " + service)


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
        print "gdt encountered an error: " + error.message
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

    root_parser = argparse.ArgumentParser(add_help=False)
    root_parser.add_argument('-cfg', '--config', type=argparse.FileType(), help='Absolute or relative path to gdt\'s config file')

    generated_parser = argparse.ArgumentParser(add_help=False, parents=[root_parser])
    generated_parser.add_argument('-p', '--program', required=True, type=argparse.FileType(), help='Absolute or relative path to program exectuable (usually ends in .full)')
    generated_parser.add_argument('-s', '--symbols', type=str, help='Absolute or relative path to root symbols directory (symbol_root_path in config.json will be ignored)')

    core_parser = subparsers.add_parser('core', help='Use when debugging a core file', parents=[generated_parser])
    core_parser.add_argument('-c', '--core', required=True, type=argparse.FileType(), help='Absolute or relative path to core file')
    core_parser.set_defaults(func=lambda args: CoreConfig(args))

    remote_parser = subparsers.add_parser('remote', help='Use when debugging a remote program', parents=[generated_parser])
    remote_parser.add_argument('-b', '--breakpoints', type=argparse.FileType(), help='Absolute or relative path to breakpoint file')
    remote_parser.add_argument('-ot', '--other-target', action='store_true', default=False, help="Use when the remote target is run on a non-QNX OS")
    remote_parser.set_defaults(func=lambda args: RemoteConfig(args))

    cmd_parser = subparsers.add_parser('cmd', help='Use to run gdb with a command file', parents=[root_parser])
    cmd_parser.add_argument('input', type=argparse.FileType(), help='Absolute or relative path to command file')
    cmd_parser.set_defaults(func=lambda args: CommandConfig(args))

    args = parser.parse_args()
    close_files(args)
    return args


def main():
    args = parse_args()
    config = args.func(args)
    run_gdb(config.gdb_path, config.command_file)
    print 'gdt session ended'


if __name__ == '__main__':
    main()
