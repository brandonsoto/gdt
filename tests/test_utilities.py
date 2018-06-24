import pytest
import gdt
import os


class TestUtilities(object):
    @pytest.mark.parametrize('test_input, expected', [
        ('192.168.33.42', True),
        ('192.168.3z.42', False),
        ('192.266.33.266', False),
        ('192', False),
        ('test', False)
    ])
    def test_validate_ipv4_address(self, test_input, expected):
        assert (gdt.validate_ipv4_address(test_input) is not None) == expected

    @pytest.mark.parametrize('test_input, expected', [
        ('0', True),
        ('65535', True),
        ('-1', False),
        ('65536', False)
    ])
    def test_validate_port(self, test_input, expected):
        assert (gdt.validate_port(test_input) is not None) == expected

    @pytest.mark.parametrize('test_input, expected', [
        (os.path.dirname(__file__), True),
        ('bobo', False)
    ])
    def test_validate_dir(self, test_input, expected):
        assert (gdt.validate_dir(test_input) is not None) == expected

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
    def test_is_cpp_file(self, test_input, expected):
        assert gdt.is_cpp_file(test_input) == expected

    @pytest.mark.parametrize('test_input, expected', [
        ('test.so', True),
        ('test.so.42', True),
        ('test.42.so', True),
        ('test.py', False),
        ('test.txt', False),
        ('test.a', False),
        ('test', False)
    ])
    def test_is_shared_library(self, test_input, expected):
        assert gdt.is_shared_library(test_input) == expected

    def test_extract_filename(self):
        assert gdt.extract_filename(__file__) == os.path.basename(__file__)[:-3]

    @pytest.mark.parametrize('test_input, expected', [
        ('C:\Project\Test', 'C:\\\\Project\\\\Test'),
        ('C:/Project/Test', 'C:/Project/Test'),
        ('C:\Project/Test', 'C:\\\\Project/Test'),
        ('TestStr', 'TestStr'),
        ('', '')
    ])
    def test_get_str_repr(self, test_input, expected):
        assert gdt.get_str_repr(test_input) == expected

    def test_verify_required_files_exist_when_missing_config_dir(self):
        old_dir = gdt.GDT_CONFIG_DIR
        gdt.GDT_CONFIG_DIR = 'bobo'

        with pytest.raises(gdt.RequiredFileMissing):
            gdt.verify_required_files_exist()

        gdt.GDT_CONFIG_DIR = old_dir

    def test_verify_required_files_exist_when_missing_gdbinit_file(self, tmpdir):
        gdt.GDT_CONFIG_DIR = tmpdir.strpath
        gdt.CORE_COMMANDS_FILE = tmpdir.join("corecommands").strpath
        gdt.DEFAULT_GDBINIT_FILE = tmpdir.join("gdbinit").strpath

        tmpdir.join("corecommands").write("")

        with pytest.raises(gdt.RequiredFileMissing):
            gdt.verify_required_files_exist()

    def test_verify_required_files_exist_when_missing_commands_file(self, tmpdir):
        gdt.GDT_CONFIG_DIR = tmpdir.strpath
        gdt.CORE_COMMANDS_FILE = tmpdir.join("corecommands").strpath
        gdt.DEFAULT_GDBINIT_FILE = tmpdir.join("gdbinit").strpath

        tmpdir.join("gdbinit").write("")

        with pytest.raises(gdt.RequiredFileMissing):
            gdt.verify_required_files_exist()

    def test_verify_required_files_exist(self, tmpdir):
        gdt.GDT_CONFIG_DIR = tmpdir.strpath
        gdt.CORE_COMMANDS_FILE = tmpdir.join("corecommands").strpath
        gdt.DEFAULT_GDBINIT_FILE = tmpdir.join("gdbinit").strpath

        tmpdir.join("corecommands").write("")
        tmpdir.join("gdbinit").write("")

        try:
            gdt.verify_required_files_exist()
        except Exception as err:
            pytest.fail("Unexpected error: " + err.message)

    def test_target_class(self):
        target = gdt.Target('192.168.33.42', 'user', 'password', '4242')
        assert target.full_address() == '192.168.33.42:4242'

    def test_gdbcommand_class(self):
        gdb_command = gdt.GDBCommand('prefix', 'value')
        assert str(gdb_command) == 'prefix value'


class TestConfigGenerator(object):
    def test_configgenerator(self, mocker):
        mock_open = mocker.patch('__builtin__.open')
        mock_dump = mocker.patch('json.dump')
        mocker.patch('gdt.ConfigFileOption', autospec=True)

        gdt.ConfigGenerator()

        mock_dump.assert_called_once()
        mock_open.assert_any_call(gdt.GDT_CONFIG_FILE, 'w')
        mock_open.assert_any_call(gdt.GDBINIT_FILE, 'w')

class TestConfigFileOption(object):
    @pytest.fixture
    def config_file_option(self):
        return gdt.ConfigFileOption(key="key", ask_user=False)

    @pytest.mark.parametrize('default_value, value, validate_func, expected', [
        ("default_value", "", lambda value: None, 'default_value'),
        ("default_value", "value", lambda value: 'value', 'value')
    ])
    def test_init_value(self, mocker, config_file_option, default_value, value, validate_func, expected):
        mock_input = mocker.patch('__builtin__.raw_input', return_value=value)
        config_file_option.ask_user = True
        config_file_option.default_value = default_value
        config_file_option.validate_func = validate_func

        config_file_option.init_value()

        mock_input.assert_called_once()
        assert config_file_option.value == expected

    def test_init_value_no_input(self, mocker, config_file_option):
        mock_input = mocker.patch('__builtin__.raw_input', return_value='bad_value')
        config_file_option.ask_user = False

        config_file_option.init_value()

        mock_input.assert_not_called()
        assert config_file_option.value is None

    @pytest.mark.parametrize('default_value, initial_desc, expected', [
        ("value", "key", "key [Default: \"value\"]: "),
        ("", "key", "key: ")
    ])
    def test_init_desc(self, config_file_option, default_value, initial_desc, expected):
        config_file_option.default_value = default_value
        config_file_option.desc = initial_desc

        config_file_option.init_desc()

        assert config_file_option.desc == expected


