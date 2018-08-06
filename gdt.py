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
GDT_CONFIG_DIRNAME = 'gdt_files'
GDT_CONFIG_DIR = os.path.join(GDT_DIR, GDT_CONFIG_DIRNAME)
GDT_CONFIG_FILENAME = 'config.json'
GDT_CONFIG_FILE = os.path.join(GDT_CONFIG_DIR, GDT_CONFIG_FILENAME)
DEFAULT_COMMANDS_FILE = os.path.join(GDT_CONFIG_DIR, 'commands.txt')
GDBINIT_FILE = os.path.join(GDT_CONFIG_DIR, 'gdbinit')
CORE_COMMANDS_FILENAME = 'core_report_commands'
CORE_COMMANDS_FILE = os.path.join(GDT_CONFIG_DIR, CORE_COMMANDS_FILENAME)
DEFAULT_CORE_REPORT_FILE = os.path.join(os.getcwd(), 'coredump_report.log')

DEFAULT_IP = "192.168.33.42"
DEFAULT_USER = "vagrant"
DEFAULT_PASSWORD = "vagrant"
DEFAULT_DEBUG_PORT = "8000"
DEFAULT_PROMPT = "# "
DEFAULT_EXCLUDED_DIRS = ['.git', '.svn', '.code']

IPV4_REGEX = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
PORT_REGEX = re.compile(r"^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$")
SHARED_LIB_REGEX = re.compile(r'\.so(\.\d+)?$')
CPP_REGEX = re.compile(r'\.h$|\.hpp$|\.c$|\.cc$|\.cpp$')


def get_str_repr(string):
    return repr(str(string))[1:-1]


def verify_required_files_exist():
    if not os.path.isdir(GDT_CONFIG_DIR):
        raise RequiredFileMissing("configuration directory: " + GDT_CONFIG_DIR)
    elif not os.path.isfile(CORE_COMMANDS_FILE):
        raise RequiredFileMissing("core dump commands file: : " + CORE_COMMANDS_FILE)


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
    return re.search(CPP_REGEX, path) is not None


def extract_filename(filepath):
    return os.path.splitext(os.path.split(filepath)[1])[0]


class GDTException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class RequiredFileMissing(GDTException):
    def __init__(self, missing_file):
        self.message = "ERROR: missing required file: " + missing_file + "\nPlease copy gdt_files directory from repository to " + GDT_DIR


class ConfigFileMissing(GDTException):
    def __init__(self, missing_file):
        self.message = "ERROR: config file does not exist: " + missing_file + "\nPlease ensure the file path is correct or run 'python " + os.path.split(__file__)[1] + " init'."


class InvalidConfig(GDTException):
    def __init__(self, name, value, config_file):
        self.message = "VALIDATION ERROR: invalid '" + name + "' in " + config_file + ": " + value


class InvalidArgs(GDTException):
    def __init__(self, message):
        self.message = "ARGUMENTS ERROR: " + message


class TelnetError(GDTException):
    def __init__(self, message):
        self.message = "TELNET ERROR: " + message


class Target:
    def __init__(self, ip, user, password, port):
        self.ip = ip
        self.user = user
        self.password = password
        self.port = port

    def full_address(self):
        return self.ip + ":" + self.port


class GDBCommand:
    def __init__(self, prefix, value):
        self.prefix = prefix
        self.value = value

    def __str__(self):
        return self.prefix + ' ' + self.value


class ConfigFileOption:
    key = ""
    value = ""

    def __init__(self, key, desc="", error_str="", validate_func=None, default_value=None, ask_user=True, value=None):
        self.key = key
        self.default_value = default_value
        self.value = value
        self.desc = desc
        self.validate_func = validate_func
        self.error_str = error_str
        self.ask_user = ask_user

        self.init_desc()
        self.init_value()

    def init_desc(self):
        if self.default_value:
            self.desc = self.desc + ' [Default: "' + self.default_value + '"]: '
        else:
            self.desc = self.desc + ': '

    def init_value(self):
        if self.ask_user:
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
            self.value = self.default_value if (value == "" and self.default_value) else value
            value = self.validate_func(self.value)
        self.value = value


class ConfigFileGenerator:
    def __init__(self, args=None):
        self.run_gdb = False
        self.generate_config_file()

    def generate_config_file(self):
        verify_required_files_exist()

        print 'This utility will walk you through creating a ' + GDT_CONFIG_FILENAME + ' file\n'

        options = [ConfigFileOption('gdb_path', 'GDB path', 'is not a file.', lambda file_path: os.path.abspath(file_path) if os.path.isfile(file_path) else None),
                   ConfigFileOption('project_root_path', 'Project root path', 'is not a directory.', validate_dir),
                   ConfigFileOption('symbol_root_path', 'Symbol root path', ' is not a directory.', validate_dir),
                   ConfigFileOption('target_ip', 'Remote target IP', 'is an invalid IPv4 address.', validate_ipv4_address, default_value=DEFAULT_IP),
                   ConfigFileOption('excluded_dir_names', ask_user=False, value=DEFAULT_EXCLUDED_DIRS),
                   ConfigFileOption('target_user', 'Remote target username', default_value=DEFAULT_USER),
                   ConfigFileOption('target_password', 'Remote target password', default_value=DEFAULT_PASSWORD),
                   ConfigFileOption('target_debug_port', 'Remote target debug port', "is an invalid port.", validate_port, DEFAULT_DEBUG_PORT),
                   ConfigFileOption('target_prompt', 'Remote target prompt', default_value=DEFAULT_PROMPT)]
        option_dict = {option.key: option.value for option in options}
        with open(GDT_CONFIG_FILE, 'w') as config_file:
            json.dump(option_dict, config_file, sort_keys=True, indent=3)
        print '\nCreated gdt configuration: ' + GDT_CONFIG_FILE


class BaseCommand:
    def __init__(self, args):
        verify_required_files_exist()
        self.check_config_exists(args.config)

        self.run_gdb = True
        self.config_file = os.path.abspath(args.config)
        self.json_data = json.load(open(args.config))
        self.gdb_path = os.path.abspath(self.json_data["gdb_path"])
        self.excluded_dir_names = [str(d) for d in self.json_data["excluded_dir_names"]]
        self.solib_separator = ";"
        self.validate_config_data()

    def check_config_exists(self, config_file):
        if not os.path.isfile(config_file):
            raise ConfigFileMissing(config_file)
        print "Using config file: " + config_file

    def validate_config_data(self):
        if not os.path.isfile(self.json_data["gdb_path"]):
            raise InvalidConfig("gdb_path", self.json_data["gdb_path"], self.config_file)
        elif not os.path.isdir(self.json_data["project_root_path"]):
            raise InvalidConfig("project_root_path", self.json_data["project_root_path"], self.config_file)
        elif not os.path.isdir(self.json_data["symbol_root_path"]):
            raise InvalidConfig("symbol_root_path", self.json_data["symbol_root_path"], self.config_file)
        elif not validate_ipv4_address(self.json_data["target_ip"]):
            raise InvalidConfig("target_ip", self.json_data["target_ip"], self.config_file)
        elif not validate_port(self.json_data["target_debug_port"]):
            raise InvalidConfig("target_debug_port", self.json_data["target_debug_port"], self.config_file)


class GeneratedCommand(BaseCommand):
    def __init__(self, args):
        BaseCommand.__init__(self, args)
        self.command_file = DEFAULT_COMMANDS_FILE
        self.project_path = os.path.abspath(args.root) if args.root else os.path.abspath(self.json_data["project_root_path"])
        self.symbol_root_path = os.path.abspath(args.symbols) if args.symbols else os.path.abspath(self.json_data["symbol_root_path"])
        self.source_separator = ";"
        self.opts = OrderedDict([("program", GDBCommand('file', get_str_repr(os.path.abspath(args.program.name))))])
        self.program_name = extract_filename(self.opts['program'].value)
        self.check_dir_exists(self.project_path, 'project')
        self.check_dir_exists(self.symbol_root_path, 'symbol')

    def check_dir_exists(self, directory, name):
        if not validate_dir(directory):
            raise IOError("ERROR: " + name + " root path does not exist or is not a directory: " + directory)

    def init_search_paths(self):
        print "Generating search paths..."
        solib_search_path = []
        source_search_path = []

        if self.symbol_root_path == self.project_path:
            solib_search_path, source_search_path = self.generate_search_paths()
        else:
            solib_search_path = self.generate_solib_search_path()
            source_search_path = self.generate_source_search_path()

        self.add_option('solib_path', GDBCommand('set solib-search-path', self.solib_separator.join(solib_search_path)))
        self.add_option('source_path', GDBCommand('dir', self.source_separator.join(source_search_path)))

    def get_search_dirs(self, dirs):
        return [d for d in dirs if os.path.basename(d) not in self.excluded_dir_names]

    def generate_search_paths(self):
        solib_search_path = []
        source_search_path = []

        for root, dirs, files in os.walk(self.project_path, topdown=True):
            dirs[:] = self.get_search_dirs(dirs)
            dirs.sort()

            has_cpp_file = any(is_cpp_file(f) for f in files)
            has_shared_lib = any(is_shared_library(f) for f in files)

            if has_shared_lib:
                solib_search_path.insert(0, get_str_repr(os.path.abspath(root)))

            if has_cpp_file and self.program_name in root:
                source_search_path.insert(0, get_str_repr(os.path.abspath(root)))
            elif has_cpp_file:
                source_search_path.append(get_str_repr(os.path.abspath(root)))

        return (solib_search_path, source_search_path)

    def generate_solib_search_path(self):
        search_path = []
        for root, dirs, files in os.walk(self.symbol_root_path, topdown=True):
            dirs[:] = self.get_search_dirs(dirs)
            dirs.sort()
            if any(is_shared_library(f) for f in files):
                search_path.insert(0, get_str_repr(os.path.abspath(root)))
        return search_path

    def generate_source_search_path(self):
        search_path = []
        for root, dirs, files in os.walk(self.project_path, topdown=True):
            dirs[:] = self.get_search_dirs(dirs)
            dirs.sort()
            has_cpp_file = any(is_cpp_file(f) for f in files)
            if has_cpp_file and self.program_name in root:
                search_path.insert(0, get_str_repr(os.path.abspath(root)))
            elif has_cpp_file:
                search_path.append(get_str_repr(os.path.abspath(root)))
        return search_path

    def generate_command_file(self):
        with open(self.command_file, 'w') as cmd_file:
            if os.path.isfile(GDBINIT_FILE):
                cmd_file.write(open(GDBINIT_FILE, 'r').read())
            for key, option in self.opts.iteritems():
                cmd_file.write("\n" + str(option))

    def add_option(self, key, option):
        self.opts[key] = option


class CoreCommand(GeneratedCommand):
    def __init__(self, args):
        self.validate_args(args)
        GeneratedCommand.__init__(self, args)
        self.init_search_paths()
        self.add_option('core', GDBCommand('core-file', get_str_repr(os.path.abspath(args.core.name))))
        self.report_file = args.report_out
        self.init(args)

    def init(self, args):
        self.generate_command_file()
        if args.report:
            self.generate_report_file()

    def validate_args(self, args):
        if not args.report and args.report_out != DEFAULT_CORE_REPORT_FILE:
            raise InvalidArgs("ERROR: Need to specify --report when using --report-out")

    def generate_report_file(self):
        old_contents = open(self.command_file, 'r').read()
        with open(self.command_file, 'w') as cmd_file:
            cmd_file.write('set logging overwrite on\n')
            cmd_file.write('set logging file ' + self.report_file + '\n')
            cmd_file.write('set logging on\n')
            cmd_file.write('set logging redirect on\n')
            cmd_file.write(old_contents + '\n')
            cmd_file.write(open(CORE_COMMANDS_FILE, 'r').read())
            print "core dump report: " + os.path.abspath(self.report_file)


class RemoteCommand(GeneratedCommand):
    def __init__(self, args):
        GeneratedCommand.__init__(self, args)
        self.is_qnx_target = not args.other_target
        self.target = Target(self.json_data["target_ip"], self.json_data["target_user"], self.json_data["target_password"], self.json_data["target_debug_port"])
        self.source_separator = ";" if self.is_qnx_target else ":"
        self.telnet = TelnetConnection(self.target, self.json_data["target_prompt"])
        self.init(args)

    def init(self, args):
        self.init_search_paths()
        self.init_target()
        self.init_pid()
        self.init_breakpoints(args.breakpoints)
        self.generate_command_file()

    def init_breakpoints(self, breakpoint_file):
        if breakpoint_file:
            self.add_option('breakpoint', GDBCommand('source', get_str_repr(os.path.abspath(breakpoint_file.name))))

    def init_target(self):
        self.add_option('target', GDBCommand('target qnx' if self.is_qnx_target else 'target extended-remote', self.target.full_address()))

    def init_pid(self):
        print 'Getting pid of ' + self.program_name + '...'
        output = self.telnet.get_pid_of(self.program_name)
        match = re.search(r'\d+ .*' + self.program_name, output)
        pid = match.group().split()[0] if match else None
        if pid:
            self.add_option('pid', GDBCommand('attach', pid))
        print 'pid of ' + self.program_name + ' = ' + str(pid)


class CmdFileCommand(BaseCommand):
    def __init__(self, args):
        BaseCommand.__init__(self, args)
        self.command_file = args.input.name


# thanks to Blayne Dennis for this class
class TelnetConnection:
    def __init__(self, target, prompt):
        self.PORT = 23
        self.TIMEOUT = 10
        self.PID_CMD = 'ps -A | grep '
        self.session = None
        self.prompt = prompt
        self.target = target
        self.connect()

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
            raise TelnetError('Server didn\'t respond')

        self.read_response('login: ')
        self.session.write('{}\n'.format(self.target.user))
        self.read_response('Password:')
        self.session.write('{}\n'.format(self.target.password))
        resp = self.read_response(self.prompt)
        if resp[-len(self.prompt):] != self.prompt:
            raise TelnetError('Invalid username or password')

    def change_prompt(self, new_prompt):
        self.prompt = new_prompt
        self.send_command('PS1="{}"'.format(new_prompt))
        self.read_response(self.prompt)

    def send_command(self, cmd):
        self.session.write('{}\n'.format(cmd))
        return self.read_response(self.prompt)

    def get_pid_of(self, service):
        return self.send_command(self.PID_CMD + service)


def run_gdb(gdb_path, command_file):
    returncode = None
    process = None
    try:
        process = subprocess.Popen(args=[gdb_path, '--command=' + command_file, '-q'])
        while returncode is None:
            try:
                returncode = process.wait()
            except KeyboardInterrupt:
                continue  # ignore interrupt to allow GDB child process to handle it
    except OSError as error:
        print "encountered an error: " + error.message
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

    base_parser = argparse.ArgumentParser(add_help=False)
    base_parser.add_argument('-cfg', '--config', default=GDT_CONFIG_FILE, help='Absolute or relative path to gdt\'s config file')

    generated_parser = argparse.ArgumentParser(add_help=False, parents=[base_parser])
    generated_parser.add_argument('-p', '--program', required=True, type=argparse.FileType(), help='Absolute or relative path to program exectuable (usually ends in .full)')
    generated_parser.add_argument('-r', '--root', help='Absolute or relative path to root project directory (project_root_path in ' + GDT_CONFIG_FILENAME + ' will be ignored)')
    generated_parser.add_argument('-s', '--symbols', help='Absolute or relative path to root symbols directory (symbol_root_path in ' + GDT_CONFIG_FILENAME + ' will be ignored)')

    core_parser = subparsers.add_parser('core', help='Use when debugging a core file', parents=[generated_parser])
    core_parser.add_argument('-c', '--core', required=True, type=argparse.FileType(), help='Absolute or relative path to core file')
    core_parser.add_argument('-rp', '--report', action='store_true', help='Generate a core dump report')
    core_parser.add_argument('--report-out', default=DEFAULT_CORE_REPORT_FILE, help='Output file for core dump report (requires -rp option)')
    core_parser.set_defaults(func=lambda args: CoreCommand(args))

    remote_parser = subparsers.add_parser('remote', help='Use when debugging a remote program', parents=[generated_parser])
    remote_parser.add_argument('-b', '--breakpoints', type=argparse.FileType(), help='Absolute or relative path to breakpoint file')
    remote_parser.add_argument('-ot', '--other-target', action='store_true', default=False, help="Use when the remote target is run on a non-QNX OS")
    remote_parser.set_defaults(func=lambda args: RemoteCommand(args))

    cmd_parser = subparsers.add_parser('cmd', help='Use to run gdb with a command file', parents=[base_parser])
    cmd_parser.add_argument('input', type=argparse.FileType(), help='Absolute or relative path to command file')
    cmd_parser.set_defaults(func=lambda args: CmdFileCommand(args))

    init_parser = subparsers.add_parser('init', help='Use to initialize ' + GDT_CONFIG_FILENAME)
    init_parser.set_defaults(func=lambda args: ConfigFileGenerator(args))

    args = parser.parse_args()
    close_files(args)
    return args


def main():
    try:
        args = parse_args()
        config = args.func(args)
        if config.run_gdb:
            run_gdb(config.gdb_path, config.command_file)
    except KeyboardInterrupt:
        pass
    except (GDTException, IOError) as err:
        print err


if __name__ == '__main__':
    main()
