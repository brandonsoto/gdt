import gdt
import mock
import os
import pytest
import socket


class MockArgs:
    config = "/config.json"
    root = "/root"
    symbols = "/symbols"
    program = mock.MagicMock()
    core = mock.MagicMock()
    report = False
    report_out = gdt.DEFAULT_CORE_REPORT_FILE
    command_file = '/command_file'
    input = mock.MagicMock()
    other_target = False
    breakpoints = ""


class MockReportArgs:
    report = False
    report_out = ""

    def __init__(self, report, report_out):
        self.report = report
        self.report_out = report_out


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
    def test_config_generator(self, mocker):
        mock_open = mocker.patch('__builtin__.open')
        mock_dump = mocker.patch('json.dump')
        mocker.patch('gdt.ConfigFileOption', autospec=True)

        generator = gdt.ConfigGenerator()

        assert not generator.run_gdb
        mock_open.assert_called_once_with(gdt.GDT_CONFIG_FILE, 'w')
        mock_dump.assert_called_once()


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

    def test_init_value_no_user_input(self, mocker, config_file_option):
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

    def test_get_valid_value(self, config_file_option, mocker):
        value = 'valid_value'
        mock_input = mocker.patch('__builtin__.raw_input', return_value=value)
        config_file_option.validate_func = mocker.MagicMock(side_effect=[None, value])

        assert config_file_option.value is None

        config_file_option.get_valid_value()

        assert config_file_option.value == value
        mock_input.assert_called_once()
        config_file_option.validate_func.assert_has_calls(calls=[mocker.call(None), mocker.call(value)])


class TestTelnetConnection(object):
    response = 'telnet response'

    @pytest.fixture
    def session(self, mocker):
        session_mock = mocker.MagicMock()
        session_mock.read_until = mocker.MagicMock(return_value=self.response)
        session_mock.write = mocker.MagicMock()
        return session_mock

    @pytest.fixture
    def telnet(self, session):
        connection = gdt.TelnetConnection(gdt.Target(gdt.DEFAULT_IP, 'user', 'passwd', gdt.DEFAULT_DEBUG_PORT), gdt.DEFAULT_PROMPT)
        connection.session = session
        return connection

    def test_read_response(self, telnet, session):
        assert telnet.read_response(gdt.DEFAULT_PROMPT) == self.response
        session.read_until.assert_called_once()

    def test_send_command(self, telnet, session):
        assert telnet.send_command('ls') == self.response
        session.write.assert_called_once_with('ls\n')
        session.read_until.assert_called_once()

    def test_get_pid_of(self, mocker, telnet, session):
        pid = '4242'
        session.read_until = mocker.MagicMock(return_value=pid)
        telnet.session = session

        assert telnet.get_pid_of('test_program') == pid
        session.write.assert_called_once_with(telnet.PID_CMD + 'test_program\n')
        session.read_until.assert_called_once()

    def test_change_prompt(self, telnet, session):
        new_prompt = "$ "

        assert telnet.prompt != new_prompt

        telnet.change_prompt(new_prompt)

        assert telnet.prompt == new_prompt
        session.write.assert_called_once_with('PS1="' + new_prompt + '"\n')
        assert session.read_until.call_count == 2

    def test_connect(self, telnet, session, mocker):
        mocker.patch('telnetlib.Telnet', return_value=session)
        session.read_until = mocker.MagicMock(return_value=telnet.prompt)

        try:
            telnet.connect()
            session.read_until.assert_has_calls(
                calls=[mocker.call('login: ', telnet.TIMEOUT),
                       mocker.call('Password:', telnet.TIMEOUT),
                       mocker.call(telnet.prompt, telnet.TIMEOUT)])
            session.write.assert_has_calls(
                calls=[mocker.call(telnet.target.user + '\n'),
                       mocker.call(telnet.target.password + '\n')])
        except Exception as err:
            pytest.fail("Unexpected error: " + err.message)

    def test_connect_server_failed(self, telnet, mocker):
        mocker.patch('telnetlib.Telnet', side_effect=socket.error)

        with pytest.raises(gdt.TelnetError):
            telnet.connect()

    def test_connect_bad_credentials(self, telnet, session, mocker):
        mocker.patch('telnetlib.Telnet', return_value=session)
        session.read_until = mocker.MagicMock(return_value='login: ')

        with pytest.raises(gdt.TelnetError):
            telnet.connect()


class TestBaseCommand(object):
    @pytest.fixture
    def mock_open(self, mocker):
        return mocker.patch('__builtin__.open', mocker.mock_open(mock=mocker.MagicMock(return_value='arg', read_data='test_file_data')))

    @pytest.fixture
    def basecmd(self, mocker, mock_open):
        json_data = {"gdb_path": "/gdb",
                     "project_root_path": "/project",
                     "symbol_root_path" : "/symbol",
                     "excluded_dir_names": [".vscode", ".git"],
                     "target_ip": gdt.DEFAULT_IP,
                     "target_debug_port": gdt.DEFAULT_DEBUG_PORT}

        mocker.patch('json.load', return_value=json_data)
        mocker.patch('os.path.isdir', return_value=True)
        mocker.patch('os.path.isfile', return_value=True)
        mocker.patch('os.path.abspath', side_effect=lambda path: path)

        args = MockArgs()
        cmd = gdt.BaseCommand(args)
        assert cmd.run_gdb
        assert cmd.json_data == json_data
        assert cmd.config_file == args.config
        assert cmd.gdb_path == os.path.abspath(json_data['gdb_path'])
        assert cmd.excluded_dir_names == json_data["excluded_dir_names"]
        return cmd

    def test_check_config_exists(self, basecmd, mocker):
        isfile_mock = mocker.patch('os.path.isfile', return_value=True)

        try:
            basecmd.check_config_exists("/home/config")
            isfile_mock.assert_called_once_with('/home/config')
        except Exception as err:
            pytest.fail("Unexpected error: " + err.message)

    def test_check_config_exists_fail(self, basecmd, mocker):
        isfile_mock = mocker.patch('os.path.isfile', return_value=False)

        with pytest.raises(gdt.ConfigFileMissing):
            basecmd.check_config_exists("/home/config")
            isfile_mock.assert_called_once_with('/home/config')


class TestGeneratedCommand(object):
    @pytest.fixture
    def mock_open(self, mocker):
        return mocker.patch('__builtin__.open', mocker.mock_open(mock=mocker.MagicMock(return_value='arg', read_data='test_file_data')))

    @pytest.fixture
    def cmd(self, mocker, mock_open):
        json_data = {"gdb_path": "/gdb",
                     "project_root_path": "/project",
                     "symbol_root_path" : "/symbol",
                     "excluded_dir_names": [".vscode", ".git"],
                     "target_ip": gdt.DEFAULT_IP,
                     "target_debug_port": gdt.DEFAULT_DEBUG_PORT}

        mocker.patch('json.load', return_value=json_data)
        mocker.patch('os.path.isdir', return_value=True)
        mocker.patch('os.path.isfile', return_value=True)
        mocker.patch('os.path.abspath', side_effect=lambda path: path)

        args = MockArgs()
        cmd = gdt.GeneratedCommand(args)
        assert cmd.run_gdb
        assert cmd.json_data == json_data
        assert cmd.config_file == args.config
        assert cmd.gdb_path == os.path.abspath(json_data['gdb_path'])
        assert cmd.excluded_dir_names == json_data["excluded_dir_names"]
        assert 'program' in cmd.opts and cmd.opts['program'].prefix == 'file'
        assert cmd.symbol_root_path == args.symbols
        assert cmd.project_path == args.root
        assert cmd.command_file == gdt.DEFAULT_COMMANDS_FILE
        return cmd

    def test_add_option(self, cmd):
        assert 'key' not in cmd.opts

        cmd.add_option("key", "option")

        assert 'key' in cmd.opts
        assert cmd.opts['key'] == 'option'

    def test_init_search_paths(self, cmd):
        assert 'solib_path' not in cmd.opts
        assert 'source_path' not in cmd.opts

        cmd.init_search_paths()

        assert 'solib_path' in cmd.opts
        assert 'source_path' in cmd.opts

    def test_generate_command_file(self, cmd, mocker, mock_open):
        cmd.generate_command_file()

        mock_open.assert_has_calls(calls=[
            mocker.call(cmd.command_file, 'w'),
            mocker.call(gdt.GDBINIT_FILE, 'r')
        ], any_order=True)
        mock_open().write.assert_called()


class TestCoreCommand(object):
    @pytest.fixture
    def mock_open(self, mocker):
        return mocker.patch('__builtin__.open', mocker.mock_open(mock=mocker.MagicMock(return_value='arg', read_data='test_file_data')))

    @pytest.fixture
    def core_cmd(self, mocker, mock_open):
        json_data = {"gdb_path": "/gdb",
                     "project_root_path": "/project",
                     "symbol_root_path" : "/symbol",
                     "excluded_dir_names": [".vscode", ".git"],
                     "target_ip": gdt.DEFAULT_IP,
                     "target_debug_port": gdt.DEFAULT_DEBUG_PORT}

        mocker.patch('json.load', return_value=json_data)
        mocker.patch('os.path.isdir', return_value=True)
        mocker.patch('os.path.isfile', return_value=True)
        mocker.patch('os.path.abspath', side_effect=lambda path: path)

        solib_mock = mocker.patch('gdt.GeneratedCommand.generate_solib_search_path', return_value="/solib")
        source_mock = mocker.patch('gdt.GeneratedCommand.generate_source_search_path', return_value="/source")

        args = MockArgs()
        cmd = gdt.CoreCommand(args)
        assert cmd.run_gdb
        assert cmd.json_data == json_data
        assert cmd.config_file == args.config
        assert cmd.gdb_path == os.path.abspath(json_data['gdb_path'])
        assert cmd.excluded_dir_names == json_data["excluded_dir_names"]
        assert 'core' in cmd.opts and cmd.opts['core'].prefix == 'core-file'
        assert cmd.report_file == args.report_out
        # TODO: program name should be checked

        solib_mock.assert_called_once()
        source_mock.assert_called_once()
        mock_open.assert_any_call(cmd.command_file, 'w')

        return cmd

    @pytest.mark.parametrize('generate_report', [False, True])
    def test_validate_args_success(self, core_cmd, generate_report):
        try:
            core_cmd.validate_args(MockReportArgs(generate_report, gdt.DEFAULT_CORE_REPORT_FILE))
        except Exception as err:
            pytest.fail("Unexpected error: " + err.message)

    def test_validate_args_fail(self, core_cmd):
        with pytest.raises(gdt.InvalidArgs):
            output_file = '/bobo'
            assert output_file != gdt.DEFAULT_CORE_REPORT_FILE
            core_cmd.validate_args(MockReportArgs(False, output_file))

    def test_generate_report(self, core_cmd, mock_open, mocker):
        core_cmd.generate_report()
        mock_open.assert_has_calls(
            [mocker.call(core_cmd.command_file, 'r'),
             mocker.call(core_cmd.command_file, 'w'),
             mocker.call(gdt.CORE_COMMANDS_FILE, 'r')],
            any_order=True)
        mock_open().write.assert_has_calls(
            [mocker.call('set logging overwrite on\n'),
             mocker.call('set logging file ' + core_cmd.report_file + '\n'),
             mocker.call('set logging on\n'),
             mocker.call('set logging redirect on\n')],
            any_order=True)


class TestCmdFileCommand(object):
    @pytest.fixture
    def mock_open(self, mocker):
        return mocker.patch('__builtin__.open', mocker.mock_open(mock=mocker.MagicMock(return_value='arg', read_data='test_file_data')))

    def test_constructor(self, mocker, mock_open):
        command_file = '/home/command_file'
        json_data = {"gdb_path": "/gdb",
                     "project_root_path": "/project",
                     "symbol_root_path" : "/symbol",
                     "excluded_dir_names": [".vscode", ".git"],
                     "target_ip": gdt.DEFAULT_IP,
                     "target_debug_port": gdt.DEFAULT_DEBUG_PORT}

        mocker.patch('json.load', return_value=json_data)
        mocker.patch('os.path.isdir', return_value=True)
        mocker.patch('os.path.isfile', return_value=True)
        mocker.patch('os.path.abspath', side_effect=lambda path: path)

        args = MockArgs()
        args.input.name = command_file
        cmd = gdt.CmdFileCommand(args)
        assert cmd.run_gdb
        assert cmd.json_data == json_data
        assert cmd.gdb_path == os.path.abspath(json_data['gdb_path'])
        assert cmd.command_file == command_file


class TestRemoteCommand(object):
    PID = '425679'
    PROGRAM_NAME = 'generic_program'

    @pytest.fixture
    def mock_open(self, mocker):
        return mocker.patch('__builtin__.open', mocker.mock_open(mock=mocker.MagicMock(return_value='arg', read_data='test_file_data')))

    @pytest.fixture
    def telnet(self, mocker):
        telnet = mocker.patch('gdt.TelnetConnection', spec=gdt.TelnetConnection)
        telnet().get_pid_of.return_value = self.PID + ' generic_program'
        return telnet

    @pytest.fixture
    def remote_cmd(self, mocker, mock_open, telnet):
        json_data = {"gdb_path": "/gdb",
                     "project_root_path": "/project",
                     "symbol_root_path" : "/symbol",
                     "excluded_dir_names": [".vscode", ".git"],
                     "target_ip": gdt.DEFAULT_IP,
                     "target_debug_port": gdt.DEFAULT_DEBUG_PORT,
                     "target_user": gdt.DEFAULT_USER,
                     "target_password": gdt.DEFAULT_PASSWORD,
                     "target_prompt": gdt.DEFAULT_PROMPT}

        mocker.patch('json.load', return_value=json_data)
        mocker.patch('os.path.isdir', return_value=True)
        mocker.patch('os.path.isfile', return_value=True)
        mocker.patch('os.path.abspath', side_effect=lambda path: path)

        solib_mock = mocker.patch('gdt.GeneratedCommand.generate_solib_search_path', return_value="/solib")
        source_mock = mocker.patch('gdt.GeneratedCommand.generate_source_search_path', return_value="/source")

        args = MockArgs()
        cmd = gdt.RemoteCommand(args)
        assert cmd.run_gdb
        assert cmd.json_data == json_data
        assert cmd.gdb_path == json_data['gdb_path']
        assert cmd.command_file == gdt.DEFAULT_COMMANDS_FILE
        assert cmd.is_qnx_target != args.other_target
        assert cmd.target.user == json_data['target_user']
        assert cmd.target.password == json_data['target_password']
        assert cmd.target.ip == json_data['target_ip']
        assert cmd.target.port == json_data['target_debug_port']
        assert cmd.source_separator == ';'

        solib_mock.assert_called_once()
        source_mock.assert_called_once()
        cmd.telnet.connect.assert_called_once()
        cmd.telnet.get_pid_of.assert_called_once()
        mock_open.assert_any_call(cmd.command_file, 'w')

        return cmd

    def test_init_breakpoints_with_file(self, remote_cmd, mocker):
        assert 'breakpoint' not in remote_cmd.opts

        args = mocker.MagicMock()
        args.name = '/breakpoint_file'

        remote_cmd.init_breakpoints(args)

        assert 'breakpoint' in remote_cmd.opts
        assert remote_cmd.opts['breakpoint'].prefix == 'source'
        assert remote_cmd.opts['breakpoint'].value == '/breakpoint_file'

    def test_init_breakpoints_without_file(self, remote_cmd):
        assert 'breakpoint' not in remote_cmd.opts

        remote_cmd.init_breakpoints(None)

        assert 'breakpoint' not in remote_cmd.opts

    def test_init_pid_with_running_process(self, remote_cmd):
        remote_cmd.program_name = self.PROGRAM_NAME
        assert 'pid' not in remote_cmd.opts

        remote_cmd.telnet.get_pid_of.reset_mock()

        remote_cmd.init_pid()

        remote_cmd.telnet.get_pid_of.assert_called_once_with(remote_cmd.program_name)
        assert 'pid' in remote_cmd.opts
        assert remote_cmd.opts['pid'].prefix == 'attach'
        assert remote_cmd.opts['pid'].value == self.PID

    @pytest.mark.parametrize('is_qnx_target, prefix', [
        (False, 'target extended-remote'),
        (True, 'target qnx')
    ])
    def test_target(self, remote_cmd, is_qnx_target, prefix):
        target = gdt.Target(gdt.DEFAULT_IP, gdt.DEFAULT_USER, gdt.DEFAULT_PASSWORD, gdt.DEFAULT_DEBUG_PORT)
        remote_cmd.program_name = self.PROGRAM_NAME
        remote_cmd.is_qnx_target = is_qnx_target
        remote_cmd.target = gdt.Target(gdt.DEFAULT_IP, gdt.DEFAULT_USER, gdt.DEFAULT_PASSWORD, gdt.DEFAULT_DEBUG_PORT)
        remote_cmd.opts.clear()

        remote_cmd.init_target()

        assert 'target' in remote_cmd.opts
        assert remote_cmd.opts['target'].prefix == prefix
        assert remote_cmd.opts['target'].value == target.full_address()

