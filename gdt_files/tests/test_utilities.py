import pytest
import gdt as g
import os


def test_validate_ipv4_address():
    assert g.validate_ipv4_address('192.168.33.42') is not None
    assert g.validate_ipv4_address('192.266.33.266') is None
    assert g.validate_ipv4_address('192') is None
    assert g.validate_ipv4_address('test') is None


def test_validate_port():
    assert g.validate_port('0') is not None
    assert g.validate_port('65535') is not None
    assert g.validate_port('-1') is None
    assert g.validate_port('65536') is None


def test_validate_dir():
    assert g.validate_dir(os.path.dirname(__file__)) is not None
    assert g.validate_dir('bobo') is None


def test_is_cpp_file():
    for f in ("test.h", "test.cpp", "test.c", "test.cc", "test.hpp"):
        assert g.is_cpp_file(f) is True
    for f in ("test.py", "test.txt", "test"):
        assert g.is_cpp_file(f) is False


def test_is_shared_library():
    for f in ("test.so", "test.so.42", "test.42.so"):
        assert g.is_shared_library(f) is True
    for f in ("test.py", "test.txt", "test", "test.a"):
        assert g.is_shared_library(f) is False


def test_extract_filename():
    assert g.extract_filename(__file__) == os.path.basename(__file__)[:-3]


def test_get_str_repr():
    assert g.get_str_repr('C:\Project\Test') == 'C:\\\\Project\\\\Test'
    assert g.get_str_repr('C:/Project/Test') == 'C:/Project/Test'
    assert g.get_str_repr('/Project/Test') == '/Project/Test'
    assert g.get_str_repr('') == ''


def test_verify_required_files_exist_when_missing_config_dir():
    old_dir = g.GDT_CONFIG_DIR
    g.GDT_CONFIG_DIR = 'bobo'

    with pytest.raises(g.RequiredFileMissing):
        g.verify_required_files_exist()

    g.GDT_CONFIG_DIR = old_dir


def test_verify_required_files_exist_when_missing_gdbinit_file(tmpdir):
    old_dir = g.GDT_CONFIG_DIR
    old_commands_file = g.CORE_COMMANDS_FILE
    old_gdbinit = g.DEFAULT_GDBINIT_FILE

    g.GDT_CONFIG_DIR = tmpdir.strpath
    g.CORE_COMMANDS_FILE = tmpdir.join("corecommands").strpath
    g.DEFAULT_GDBINIT_FILE = tmpdir.join("gdbinit").strpath

    tmpdir.join("corecommands").write("")

    with pytest.raises(g.RequiredFileMissing):
        g.verify_required_files_exist()

    g.CORE_COMMANDS_FILE = old_commands_file
    g.DEFAULT_GDBINIT_FILE = old_gdbinit
    g.GDT_CONFIG_DIR = old_dir


def test_verify_required_files_exist_when_missing_commands_file(tmpdir):
    old_dir = g.GDT_CONFIG_DIR
    old_commands_file = g.CORE_COMMANDS_FILE
    old_gdbinit = g.DEFAULT_GDBINIT_FILE

    g.GDT_CONFIG_DIR = tmpdir.strpath
    g.CORE_COMMANDS_FILE = tmpdir.join("corecommands").strpath
    g.DEFAULT_GDBINIT_FILE = tmpdir.join("gdbinit").strpath

    tmpdir.join("gdbinit").write("")

    with pytest.raises(g.RequiredFileMissing):
        g.verify_required_files_exist()

    g.CORE_COMMANDS_FILE = old_commands_file
    g.DEFAULT_GDBINIT_FILE = old_gdbinit
    g.GDT_CONFIG_DIR = old_dir


def test_verify_required_files_exist(tmpdir):
    old_dir = g.GDT_CONFIG_DIR
    old_commands_file = g.CORE_COMMANDS_FILE
    old_gdbinit = g.DEFAULT_GDBINIT_FILE

    g.GDT_CONFIG_DIR = tmpdir.strpath
    g.CORE_COMMANDS_FILE = tmpdir.join("corecommands").strpath
    g.DEFAULT_GDBINIT_FILE = tmpdir.join("gdbinit").strpath

    tmpdir.join("corecommands").write("")
    tmpdir.join("gdbinit").write("")

    try:
        g.verify_required_files_exist()
    except Exception as err:
        pytest.fail("Unexpected error: " + err.message)

    g.CORE_COMMANDS_FILE = old_commands_file
    g.DEFAULT_GDBINIT_FILE = old_gdbinit
    g.GDT_CONFIG_DIR = old_dir


def test_target_class():
    target = g.Target('192.168.33.42', 'user', 'password', '4242')
    assert target.full_address() == '192.168.33.42:4242'


def test_gdbcommand_class():
    gdb_command = g.GDBCommand('prefix', 'value')
    assert str(gdb_command) == 'prefix value'

