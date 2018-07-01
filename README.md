# GDT

<a href="https://codeclimate.com/github/brandonsoto/gdt/maintainability"><img src="https://api.codeclimate.com/v1/badges/c203adcc92be588cf10d/maintainability" /></a>
[![Build Status](https://travis-ci.org/brandonsoto/gdt.svg?branch=master)](https://travis-ci.org/brandonsoto/gdt)
[![Test Coverage](https://api.codeclimate.com/v1/badges/c203adcc92be588cf10d/test_coverage)](https://codeclimate.com/github/brandonsoto/gdt/test_coverage)

# What does the tool do?

GDT (GDB-Developer-Tool): developer script that allows you to quickly and easily debug a remote target or local core dump. It's essentially a wrapper around GDB that can automatically attach to a remote process and generate GDB's solib-search-path and dir options for you.

## Features
- Debug a remote process
- Debug a local core file
- Create a report summary for a core dump

# How can I use the tool?

```bash
python gdt.py -h
python gdt.py init -h
python gdt.py remote -h
python gdt.py core -h
python gdt.py cmd -h
```

## Running gdt for the first time

When using gdt for the first time, you will need to generate config.json. You can find more info on config.json below. Please generate this file using:

```bash
python gdt.py init
```

gdt requires that gdt_files/config.json exists. You can also provide a config file using the -cfg command-line option.

## Remote Debugging a local build
1. Build the module of your choice with symbols enabled. For instance:
```bash
g++ -g3 main.cpp -o bin/program.full
```
2. Update binary on target and reboot
3. Set project_root_path in config.json to your project's root directory (or specify -r command-line option in step 5)
4. Set symbols_root_path in config.json to your project's root directory (or specify -s command-line option in step 5)
5. Run
```bash
python gdt.py remote -p bin/program.full
```

## Debugging a Core File from a Local Build
1. Set project_root_path in config.json to your project's root directory (or specify -r command-line option in step 4)
2. Set symbols_root_paths in config.json to your project's root directory (or specify -s command-line option in step 4)
3. Copy core file from target to host machine
4. Run
```bash
python gdt.py core -p bin/program.full -c program.core
```

## Generating a core dump report

gdt allows you to automatically create a core dump report. This is very useful when you need to attach core dump summaries to tickets. All you need to do is modify the last step from 'Debugging a Core File from a Local Build'
```bash
python gdt.py core -p bin/program.full -c program.core -rp --report-out logs/coredump.log
```

The `--report-out` argument is completely optional. gdt will generate 'gdt_files/coredump_report.log' by default.

## Debug using a GDB Command File
```bash
python gdt.py cmd project/gdb_commands.txt
```

# Configuration
## config.json

This file is crucial to gdt. Make sure to generate it when you use gdt for the first time by running `python gdt.py init`. It can be found in gdt_files/. It contains path and target configurations. Customize it however you need to (Note: I recommend keeping the existing names in excluded_dir_names as it helps the path generation algorithm). You will find the following options:
```code
{
    "gdb_path": "GDB_PATH",                      // path to GDB executable
    "project_root_path": "PROJECT_ROOT",         // path to project's root directory
    "symbol_root_path": "SYMBOL_ROOT_PATH",      // path to root symbol directory
    "excluded_dir_names": ["EXCLUDED_DIR_NAME"], // names of directories to be excluded from solib/source path generating (ex. .svn, .git, .vscode, etc.)
	"target_ip": "TARGET_IP4",                   // the target's IPv4 address (default: "192.168.33.42")
    "target_user": "TARGET_USER",                // the target's username (default: "vagrant")
    "target_password": "TARGET_PASSWORD",        // the target's password (default: "vagrant")
    "target_debug_port": "DEBUG_PORT",           // the port to connect GDB to (default: "8000")
    "target_prompt": "TELNET_PROMPT"             // the target's command line prompt (default: "# ")
}
```

## gdbinit

You can learn more about gdbinit files at http://man7.org/linux/man-pages/man5/gdbinit.5.html

This file contains GDB commands to automatically execute during GDB startup. It includes useful routines and options I've found, but feel free to customize it however you'd like. It can be found in gdt_files. gdt uses this file when it generates commands.txt. Here's an example of what it may look like:
```code
# prints Qt5 string (http://silmor.de/qtstuff.printqstring.php)
define print_qstring
  set $d=$arg0.d
  printf "(Qt5 QString)0x%x length=%i: \"",&$arg0,$d->size
  set $i=0
  set $ca=(const ushort*)(((const char*)$d)+$d->offset)
  while $i < $d->size
    set $c=$ca[$i++]
    if $c < 32 || $c > 127
      printf "\\u%04x", $c
    else
      printf "%c" , (char)$c
    end
  end
  printf "\"\n"
end

set pagination off
set auto-solib-add on
```

## core_report_commands

This file is contains gdb commands to generate a core dump report summary. It can be found in gdt_files/. Feel free to modify it if it doesn't fit your needs.

## commands.txt

This is a file that gdt generates to pass to GDB. It can be found in gdt_files. Any changes you make this file will be overwritten except when using the cmd gdt command-line option.