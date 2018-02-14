import argparse

DEFAULT_TARGET_IP = "192.168.1.26"
DEFAULT_TARGET_TELNET_PORT = "23"
DEFAULT_TARGET_DEBUG_PORT = "8000"
DEFAULT_TARGET_PASSWORD = "vagrant"
DEFAULT_QNX_SDK = "D:\\Projects\\qnx600"
DEFAULT_GDB = DEFAULT_QNX_SDK + "\\usr\\bin\\ntoarmv7-gdb.exe"
DEFAULT_SYMBOLS = "D:\\Projects\\Symbols"

def parse_args():
    parser = argparse.ArgumentParser(
        description='GDB Developer Tool: developer script to quickly and easily get GDB setup')
    parser.add_argument(
        '--ip',
        type=str,
        default=DEFAULT_TARGET_IP,
        help="Target's IP address (default: " + DEFAULT_TARGET_IP + ")")
    parser.add_argument(
        '-c',
        '--core',
        type=str,
        help="Path to core file (must be used with -m argument)") 
    parser.add_argument(
        '-s',
        '--symbols',
        type=str,
        default=DEFAULT_SYMBOLS
        help="Path to debug symbols"
    parser.add_argument(
        '-m',
        '--module',
        type=str,
        help="Path to module executable")
    parser.add_argument(
        '-q',
        '--qnx',
        type=str,
        default=DEFAULT_QNX_SDK,
        help="Path to QNX SDK (default: " + DEFAULT_QNX_SDK + ")")
    parser.add_argument(
        '-g',
        '--gdb',
        type=str,
        default=DEFAULT_GDB,
        help="Path to GDB executable (default: " + DEFAULT_GDB + ")")
    args = parser.parse_args()
    print args


def main():
    parse_args()


if __name__ == '__main__':
    main()