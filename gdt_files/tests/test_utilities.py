import pytest
import gdt as g
import os


@pytest.mark.parametrize('test_input, expected', [
    ('192.168.33.42', True),
    ('192.168.3z.42', False),
    ('192.266.33.266', False),
    ('192', False),
    ('test', False)
])
def test_validate_ipv4_address(test_input, expected):
    assert (g.validate_ipv4_address(test_input) is not None) == expected


@pytest.mark.parametrize('test_input, expected', [
    ('0', True),
    ('65535', True),
    ('-1', False),
    ('65536', False)
])
def test_validate_port(test_input, expected):
    assert (g.validate_port(test_input) is not None) == expected


@pytest.mark.parametrize('test_input, expected', [
    (os.path.dirname(__file__), True),
    ('bobo', False)
])
def test_validate_dir(test_input, expected):
    assert (g.validate_dir(test_input) is not None) == expected


@pytest.mark.parametrize('test_input, expected', [
    ('test.h', True),
    ('test.cc', True),
    ('test.cpp', True),
    ('test.c', True),
    ('test.cc', True),
    ('test.hpp', True),
    ('test.py', False),
    ('test.txt', False),
    ('test', False)
])
def test_is_cpp_file(test_input, expected):
    assert g.is_cpp_file(test_input) == expected


@pytest.mark.parametrize('test_input, expected', [
    ('test.so', True),
    ('test.so.42', True),
    ('test.42.so', True),
    ('test.py', False),
    ('test.txt', False),
    ('test.a', False),
    ('test', False)
])
def test_is_shared_library(test_input, expected):
    assert g.is_shared_library(test_input) == expected


def test_extract_filename():
    assert g.extract_filename(__file__) == os.path.basename(__file__)[:-3]


@pytest.mark.parametrize('test_input, expected', [
    ('C:\Project\Test', 'C:\\\\Project\\\\Test'),
    ('C:/Project/Test', 'C:/Project/Test'),
    ('C:\Project/Test', 'C:\\\\Project/Test'),
    ('TestStr', 'TestStr'),
    ('', '')
])
def test_get_str_repr(test_input, expected):
    assert g.get_str_repr(test_input) == expected


def test_verify_required_files_exist_when_missing_config_dir():
    old_dir = g.GDT_CONFIG_DIR
    g.GDT_CONFIG_DIR = 'bobo'

    with pytest.raises(g.RequiredFileMissing):
        g.verify_required_files_exist()

    g.GDT_CONFIG_DIR = old_dir


def test_verify_required_files_exist_when_missing_gdbinit_file(tmpdir):
    g.GDT_CONFIG_DIR = tmpdir.strpath
    g.CORE_COMMANDS_FILE = tmpdir.join("corecommands").strpath
    g.DEFAULT_GDBINIT_FILE = tmpdir.join("gdbinit").strpath

    tmpdir.join("corecommands").write("")

    with pytest.raises(g.RequiredFileMissing):
        g.verify_required_files_exist()


def test_verify_required_files_exist_when_missing_commands_file(tmpdir):
    g.GDT_CONFIG_DIR = tmpdir.strpath
    g.CORE_COMMANDS_FILE = tmpdir.join("corecommands").strpath
    g.DEFAULT_GDBINIT_FILE = tmpdir.join("gdbinit").strpath

    tmpdir.join("gdbinit").write("")

    with pytest.raises(g.RequiredFileMissing):
        g.verify_required_files_exist()


def test_verify_required_files_exist(tmpdir):
    g.GDT_CONFIG_DIR = tmpdir.strpath
    g.CORE_COMMANDS_FILE = tmpdir.join("corecommands").strpath
    g.DEFAULT_GDBINIT_FILE = tmpdir.join("gdbinit").strpath

    tmpdir.join("corecommands").write("")
    tmpdir.join("gdbinit").write("")

    try:
        g.verify_required_files_exist()
    except Exception as err:
        pytest.fail("Unexpected error: " + err.message)


def test_target_class():
    target = g.Target('192.168.33.42', 'user', 'password', '4242')
    assert target.full_address() == '192.168.33.42:4242'


def test_gdbcommand_class():
    gdb_command = g.GDBCommand('prefix', 'value')
    assert str(gdb_command) == 'prefix value'

