import gdt
import mock
import os
import pytest
import socket


JSON_DATA = {"gdb_path": "/gdb",
             "project_root_path": "/project",
             "symbol_root_path" : "/symbol",
             "excluded_dir_names": [".vscode", ".git"],
             "target_ip": gdt.DEFAULT_IP,
             "target_debug_port": gdt.DEFAULT_DEBUG_PORT,
             "target_user": gdt.DEFAULT_USER,
             "target_password": gdt.DEFAULT_PASSWORD,
             "target_prompt": gdt.DEFAULT_PROMPT}
PROGRAM_NAME = 'test_program'
PROGRAM_MOCK = mock.MagicMock()
PROGRAM_MOCK.name = '/project/' + PROGRAM_NAME + '.full'


@pytest.fixture
def os_mocks(mocker):
    return mocker.patch.multiple('os.path', isdir=mock.MagicMock(return_value=True),
                                 isfile=mock.MagicMock(return_value=True),
                                 abspath=mock.MagicMock(side_effect=lambda path: path))


@pytest.fixture
def json_mocks(mocker):
    return mocker.patch.multiple('json', load=mock.MagicMock(return_value=JSON_DATA),
                                 dump=mock.MagicMock())


@pytest.fixture
def mock_open(mocker):
    return mocker.patch('__builtin__.open', mocker.mock_open(mock=mocker.MagicMock(return_value='arg', read_data='test_file_data')))


class MockArgs:
    config = "/config.json"
    root = "/root"
    symbols = "/symbols"
    program = PROGRAM_MOCK
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
    @pytest.mark.skip(reason="This test needs to be rewritten to account for calling os.path.abspath")
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
    def test_config_generator(self, mocker, mock_open):
        mock_dump = mocker.patch('json.dump')
        mocker.patch('gdt.ConfigFileOption', autospec=True)

        generator = gdt.ConfigFileGenerator()

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
        return session_mock

    @pytest.fixture
    def telnet(self, session, mocker):
        connect_mock = mocker.patch('gdt.TelnetConnection.connect')
        target = gdt.Target(gdt.DEFAULT_IP, 'user', 'passwd', gdt.DEFAULT_DEBUG_PORT)
        port = gdt.DEFAULT_PROMPT

        connection = gdt.TelnetConnection(target, port)

        assert connection.prompt == gdt.DEFAULT_PROMPT
        assert connection.session is None
        assert target.ip == connection.target.ip
        assert target.user == connection.target.user
        assert target.password == connection.target.password
        assert target.port == connection.target.port
        connect_mock.assert_called_once()

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
        mocker.stopall()
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
        mocker.stopall()
        mocker.patch('telnetlib.Telnet', side_effect=socket.error)

        with pytest.raises(gdt.TelnetError):
            telnet.connect()

    def test_connect_bad_credentials(self, telnet, session, mocker):
        mocker.stopall()
        mocker.patch('telnetlib.Telnet', return_value=session)
        session.read_until = mocker.MagicMock(return_value='login: ')

        with pytest.raises(gdt.TelnetError):
            telnet.connect()

    def test_close_with_active_session(self, telnet):
        telnet.session.reset_mock()
        assert telnet.session is not None
        telnet.close()
        telnet.session.close.assert_called_once()

    def test_close_with_no_session(self, telnet, session):
        telnet.session.reset_mock()
        telnet.session = None
        telnet.close()
        session.close.assert_not_called()


class TestBaseCommand(object):
    @pytest.fixture
    def basecmd(self, mock_open, os_mocks, json_mocks):
        args = MockArgs()

        cmd = gdt.BaseCommand(args)

        assert cmd.run_gdb
        assert cmd.json_data == JSON_DATA
        assert cmd.config_file == args.config
        assert cmd.gdb_path == os.path.abspath(JSON_DATA['gdb_path'])
        assert cmd.excluded_dir_names == JSON_DATA["excluded_dir_names"]

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
    def cmd(self, mocker, mock_open, os_mocks, json_mocks):
        check_dir_mock = mocker.patch('gdt.GeneratedCommand.check_dir_exists')
        args = MockArgs()

        cmd = gdt.GeneratedCommand(args)

        assert cmd.run_gdb
        assert cmd.json_data == JSON_DATA
        assert cmd.config_file == args.config
        assert cmd.gdb_path == os.path.abspath(JSON_DATA['gdb_path'])
        assert cmd.excluded_dir_names == JSON_DATA["excluded_dir_names"]
        assert 'program' in cmd.opts and cmd.opts['program'].prefix == 'file'
        assert cmd.symbol_root_path == args.symbols
        assert cmd.project_path == args.root
        assert cmd.command_file == gdt.DEFAULT_COMMANDS_FILE
        assert cmd.program_name == PROGRAM_NAME

        check_dir_mock.assert_has_calls(
            calls=[mocker.call(cmd.project_path, 'project'),
                   mocker.call(cmd.symbol_root_path, 'symbol')])

        return cmd

    def test_check_required_dir_success(self, cmd, mocker):
        mocker.stopall()
        validate_dir_mock = mocker.patch('gdt.validate_dir', return_value=True)

        try:
            cmd.check_dir_exists(cmd.project_path, 'test_dir')
            validate_dir_mock.assert_called_once_with(cmd.project_path)
        except Exception as err:
            pytest.fail("Unexpected error: " + err.message)

    def test_check_required_dir_fail(self, cmd, mocker):
        mocker.stopall()
        validate_dir_mock = mocker.patch('gdt.validate_dir', return_value=False)

        with pytest.raises(IOError):
            cmd.check_dir_exists(cmd.project_path, 'test_dir')
            validate_dir_mock.assert_called_once_with(cmd.project_path)

    def test_add_option(self, cmd):
        assert 'key' not in cmd.opts

        cmd.add_option("key", "option")

        assert 'key' in cmd.opts
        assert cmd.opts['key'] == 'option'

    def test_init_search_paths_with_same_dirs(self, cmd, mocker):
        search_paths_mock = mocker.patch('gdt.GeneratedCommand.generate_search_paths', return_value=(['/solib1', '/solib2'], ['/src1', '/src2']))
        solib_path_mock = mocker.patch('gdt.GeneratedCommand.generate_source_search_path', return_value=[])
        source_path_mock = mocker.patch('gdt.GeneratedCommand.generate_solib_search_path', return_value=[])
        cmd.symbol_root_path = "/root"
        cmd.project_path = "/root"

        assert cmd.symbol_root_path == cmd.project_path
        assert 'solib_path' not in cmd.opts
        assert 'source_path' not in cmd.opts

        cmd.init_search_paths()

        assert 'solib_path' in cmd.opts
        assert 'source_path' in cmd.opts
        assert cmd.opts['solib_path'].prefix == 'set solib-search-path' and cmd.opts['solib_path'].value == '/solib1;/solib2'
        assert cmd.opts['source_path'].prefix == 'dir' and cmd.opts['source_path'].value == '/src1;/src2'
        solib_path_mock.assert_not_called()
        source_path_mock.assert_not_called()
        search_paths_mock.assert_called_once()

    def test_init_search_paths_with_different_dirs(self, cmd, mocker):
        search_paths_mock = mocker.patch('gdt.GeneratedCommand.generate_search_paths', return_value=())
        solib_path_mock = mocker.patch('gdt.GeneratedCommand.generate_source_search_path', return_value=['/src1', '/src2'])
        source_path_mock = mocker.patch('gdt.GeneratedCommand.generate_solib_search_path', return_value=['/solib1', '/solib2'])

        assert cmd.symbol_root_path != cmd.project_path
        assert 'solib_path' not in cmd.opts
        assert 'source_path' not in cmd.opts

        cmd.init_search_paths()

        assert 'solib_path' in cmd.opts
        assert 'source_path' in cmd.opts
        assert cmd.opts['solib_path'].prefix == 'set solib-search-path' and cmd.opts['solib_path'].value == '/solib1;/solib2'
        assert cmd.opts['source_path'].prefix == 'dir' and cmd.opts['source_path'].value == '/src1;/src2'
        solib_path_mock.assert_called_once()
        source_path_mock.assert_called_once()
        search_paths_mock.assert_not_called()

    def test_generate_command_file(self, cmd, mocker, mock_open):
        cmd.generate_command_file()

        mock_open.assert_has_calls(calls=[
            mocker.call(cmd.command_file, 'w'),
            mocker.call(gdt.GDBINIT_FILE, 'r')
        ], any_order=True)
        mock_open().write.assert_called()

    def test_generate_solib_search_path(self, cmd, tmpdir, mocker):
        mocker.stopall()
        solib_dir = tmpdir.mkdir('solib_a')
        solib_dir2 = tmpdir.mkdir('solib_z')
        static_dir = tmpdir.mkdir('static')
        src_dir = tmpdir.mkdir('src')
        excluded_dir = tmpdir.mkdir('.git')
        nested_solib_dir = solib_dir.mkdir('more_solib')
        nested_solib_dir2 = src_dir.mkdir('libs')

        solib_dir.join('shared_lib.so').write('')
        solib_dir2.join('shared_lib.so.42').write('')
        static_dir.join('static_lib.a').write('')
        src_dir.join('main.cpp').write('')
        excluded_dir.join('shared_lib_2.so').write('')
        nested_solib_dir.join('test_lib.so').write('')
        nested_solib_dir2.join('test.so.77').write('')

        expected = [nested_solib_dir2.strpath, solib_dir2.strpath, nested_solib_dir.strpath, solib_dir.strpath]

        cmd.symbol_root_path = tmpdir.strpath

        actual = cmd.generate_solib_search_path()

        assert expected == actual

    def test_generate_solib_search_path_empty(self, cmd, tmpdir):
        cmd.symbol_root_path = tmpdir.strpath
        assert [] == cmd.generate_solib_search_path()

    def test_generate_source_search_path(self, cmd, tmpdir, mocker):
        mocker.stopall()
        solib_dir = tmpdir.mkdir('solib')
        static_dir = tmpdir.mkdir('static')
        src_dir = tmpdir.mkdir('src')
        excluded_dir = tmpdir.mkdir('.git')
        source_dir2 = tmpdir.mkdir(PROGRAM_NAME)
        nested_src_dir = src_dir.mkdir('nested')
        nested_src_dir_2 = solib_dir.mkdir('src')

        solib_dir.join('shared_lib.so').write('')
        static_dir.join('static_lib.a').write('')
        src_dir.join('main.cpp').write('')
        source_dir2.join('utility.h').write('')
        excluded_dir.join('excluded.cpp').write('')
        nested_src_dir.join('other.c').write('')
        nested_src_dir_2.join('other.cpp').write('')

        expected = [source_dir2.strpath, nested_src_dir_2.strpath, src_dir.strpath, nested_src_dir.strpath]

        cmd.program_name = PROGRAM_NAME
        cmd.project_path = tmpdir.strpath

        actual = cmd.generate_source_search_path()

        assert expected == actual

    def test_generate_source_search_path_empty(self, cmd, tmpdir):
        cmd.symbol_root_path = tmpdir.strpath
        assert [] == cmd.generate_source_search_path()


class TestCoreCommand(object):
    @pytest.fixture
    def core_cmd(self, mocker, mock_open, os_mocks, json_mocks):
        search_path_mock = mocker.patch('gdt.GeneratedCommand.init_search_paths')
        init_mock = mocker.patch('gdt.CoreCommand.init')
        args = MockArgs()

        cmd = gdt.CoreCommand(args)

        assert cmd.run_gdb
        assert cmd.json_data == JSON_DATA
        assert cmd.config_file == args.config
        assert cmd.gdb_path == os.path.abspath(JSON_DATA['gdb_path'])
        assert cmd.excluded_dir_names == JSON_DATA["excluded_dir_names"]
        assert 'core' in cmd.opts and cmd.opts['core'].prefix == 'core-file'
        assert cmd.report_file == args.report_out
        assert cmd.program_name == PROGRAM_NAME
        search_path_mock.assert_called_once()
        init_mock.assert_called_once()

        return cmd

    def test_init_with_no_report(self, mocker, core_cmd):
        mocker.stopall()

        gen_mock = mocker.patch('gdt.GeneratedCommand.generate_command_file')
        gen_report_mock = mocker.patch('gdt.CoreCommand.generate_report_file')

        core_cmd.init(MockReportArgs(False, ""))

        gen_mock.assert_called_once()
        gen_report_mock.assert_not_called()

    def test_init_with_report(self, mocker, core_cmd):
        mocker.stopall()

        gen_mock = mocker.patch('gdt.GeneratedCommand.generate_command_file')
        gen_report_mock = mocker.patch('gdt.CoreCommand.generate_report_file')

        core_cmd.init(MockReportArgs(True, ""))

        gen_mock.assert_called_once()
        gen_report_mock.assert_called_once()

    @pytest.mark.parametrize('generate_report_file', [False, True])
    def test_validate_args_success(self, core_cmd, generate_report_file):
        try:
            core_cmd.validate_args(MockReportArgs(generate_report_file, gdt.DEFAULT_CORE_REPORT_FILE))
        except Exception as err:
            pytest.fail("Unexpected error: " + err.message)

    def test_validate_args_fail(self, core_cmd):
        with pytest.raises(gdt.InvalidArgs):
            output_file = '/bobo'
            assert output_file != gdt.DEFAULT_CORE_REPORT_FILE
            core_cmd.validate_args(MockReportArgs(False, output_file))

    def test_generate_report_file(self, core_cmd, mock_open, mocker):
        core_cmd.generate_report_file()
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
    def test_constructor(self, mock_open, os_mocks, json_mocks):
        command_file = '/home/command_file'
        args = MockArgs()
        args.input.name = command_file

        cmd = gdt.CmdFileCommand(args)

        assert cmd.run_gdb
        assert cmd.json_data == JSON_DATA
        assert cmd.gdb_path == os.path.abspath(JSON_DATA['gdb_path'])
        assert cmd.command_file == command_file


class TestRemoteCommand(object):
    PID = '425679'

    @pytest.fixture
    def telnet(self, mocker):
        telnet = mocker.patch('gdt.TelnetConnection', spec=gdt.TelnetConnection)
        telnet().get_pid_of.return_value = self.PID + ' ' + PROGRAM_NAME
        return telnet

    @pytest.fixture
    def remote_cmd(self, mocker, mock_open, telnet, os_mocks, json_mocks):
        init_mock = mocker.patch('gdt.RemoteCommand.init')
        args = MockArgs()

        cmd = gdt.RemoteCommand(args)

        assert cmd.run_gdb
        assert cmd.json_data == JSON_DATA
        assert cmd.gdb_path == JSON_DATA['gdb_path']
        assert cmd.command_file == gdt.DEFAULT_COMMANDS_FILE
        assert cmd.is_qnx_target != args.other_target
        assert cmd.target.user == JSON_DATA['target_user']
        assert cmd.target.password == JSON_DATA['target_password']
        assert cmd.target.ip == JSON_DATA['target_ip']
        assert cmd.target.port == JSON_DATA['target_debug_port']
        assert cmd.source_separator == ';'
        assert cmd.program_name == PROGRAM_NAME

        init_mock.assert_called_once()

        return cmd

    def test_init(self, remote_cmd, mocker):
        mocker.stopall()

        search_mock = mocker.patch('gdt.GeneratedCommand.init_search_paths')
        gen_mock = mocker.patch('gdt.GeneratedCommand.generate_command_file')
        target_mock = mocker.patch('gdt.RemoteCommand.init_target')
        pid_mock = mocker.patch('gdt.RemoteCommand.init_pid')
        breakpoint_mock = mocker.patch('gdt.RemoteCommand.init_breakpoints')

        args = mock.sentinel
        args.breakpoints = 'breakpoints'

        remote_cmd.init(args)

        search_mock.assert_called_once()
        target_mock.assert_called_once()
        pid_mock.assert_called_once()
        breakpoint_mock.assert_called_once_with(args.breakpoints)
        gen_mock.assert_called_once()

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
        assert 'pid' not in remote_cmd.opts

        remote_cmd.init_pid()

        remote_cmd.telnet.get_pid_of.assert_called_once_with(remote_cmd.program_name)
        assert 'pid' in remote_cmd.opts
        assert remote_cmd.opts['pid'].prefix == 'attach'
        assert remote_cmd.opts['pid'].value == self.PID

    def test_init_pid_with_unknown_process(self, remote_cmd):
        remote_cmd.program_name = 'unknown_program'
        assert 'pid' not in remote_cmd.opts

        remote_cmd.init_pid()

        remote_cmd.telnet.get_pid_of.assert_called_once_with(remote_cmd.program_name)
        assert 'pid' not in remote_cmd.opts

    @pytest.mark.parametrize('is_qnx_target, prefix', [
        (False, 'target extended-remote'),
        (True, 'target qnx')
    ])
    def test_init_target(self, remote_cmd, is_qnx_target, prefix):
        target = gdt.Target(gdt.DEFAULT_IP, gdt.DEFAULT_USER, gdt.DEFAULT_PASSWORD, gdt.DEFAULT_DEBUG_PORT)
        remote_cmd.program_name = PROGRAM_NAME
        remote_cmd.is_qnx_target = is_qnx_target
        remote_cmd.target = gdt.Target(gdt.DEFAULT_IP, gdt.DEFAULT_USER, gdt.DEFAULT_PASSWORD, gdt.DEFAULT_DEBUG_PORT)
        remote_cmd.opts.clear()

        remote_cmd.init_target()

        assert 'target' in remote_cmd.opts
        assert remote_cmd.opts['target'].prefix == prefix
        assert remote_cmd.opts['target'].value == target.full_address()
