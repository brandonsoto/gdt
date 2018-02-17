import argparse
import json
import os
import re
import socket
import subprocess
import telnetlib


def is_dir(path):
    if path and (not os.path.isabs(path) or not os.path.isdir(path)):
        raise Exception("directory does not exist - " + path)


def is_file(path):
    if path and (not os.path.isabs(path) or not os.path.isfile(path)):
        raise Exception("file does not exist - " + path)


class Config:
    def __init__(self, args):
        data = json.load(open('gdt_config.json'))

        self.module_path = args.module if args.module else data["module_path"]
        self.core_path = args.core
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
        self.qnx_sdk_path = data["qnx_sdk_path"]
        self.solib_search_path = ""
        self.validate()

    def validate(self):
        print "Validating configuration..."

        if self.core_path and not self.module_path:
            raise Exception("must specify module (-m) when core file is provided")

        for file_path in [self.module_path, self.core_path, self.gdb_path, self.command_file if not self.generate_command_file else None]:
            is_file(file_path)

        for dir_path in [self.symbols_path, self.qnx_sdk_path, self.project_path]:
            is_dir(dir_path)

        print "Finished validating configuration"


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


def run_gdb(gdb_path, command_file):
    print "Starting gdb..."
    try:
        subprocess.call([gdb_path, "--command=" + command_file])
        print "Debugging session ended successfully"
    except Exception as exception:
        subprocess.call("reset")
        print "Debugging session ended in an error: " + exception.message


# TODO(brandon): what is the best way to handle multiple results?
def get_service_pid(config):
    service_name = extract_service_name(config.module_path)
    telnet = TelnetConnection(ip=config.target_ip, user=config.target_user, password=config.target_password,
                              prompt=config.target_prompt)
    command_output = telnet.send_command("ps -A | grep -w " + service_name)
    pid_list = re.findall(r'\b\d+\b', command_output)

    if len(pid_list) > 0:
        return pid_list[0]
    else:
        return None


def extract_service_name(service_path):
    filename = os.path.split(service_path)[1]
    end_index = filename.rfind(".")
    if end_index in range(0, len(filename)):
        return filename[:end_index]
    else:
        return filename


def generate_gdb_command_file(config):
    print "Generating gdb command file..."
    # TODO(brandon): need to figure out best way to generate solib-search-path
    # TODO(brandon): need to search for src directories based on project path - this will generate dir variable
    cmd_file = open(config.command_file, 'w')
    cmd_file.write('set solib-search-path ' + config.solib_search_path + '\n')
    cmd_file.write('set auto-solib-add on\n')
    cmd_file.write('file ' + config.module_path + '\n')
    if config.core_path:
        cmd_file.write('core-file ' + config.core_path + '\n')
    else:
        # cmd_file.write('target qnx ' + config.target_ip + ':' + config.target_debug_port + '\n') TODO: reenable for qnx target
        cmd_file.write('target extended-remote ' + config.target_ip + ':' + config.target_debug_port + '\n')
        pid = get_service_pid(config)
        if pid:
            cmd_file.write('attach ' + pid + '\n')
    cmd_file.close()
    print "Finished generating gdb command file"


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
        '--source',
        type=str,
        help="Paths to source files (default: separate paths with ';')")
    parser.add_argument(
        '--commands',
        type=str,
        help="Path to GDB command file (This script will generate its own if not provided)")
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    config = Config(args)

    if config.generate_command_file:
        generate_gdb_command_file(config)

    run_gdb(config.gdb_path, config.command_file)
    print "Done!"


if __name__ == '__main__':
    main()
