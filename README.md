# GDT

<a href="https://codeclimate.com/github/brandonsoto/gdt/maintainability"><img src="https://api.codeclimate.com/v1/badges/c203adcc92be588cf10d/maintainability" /></a>
[![Build Status](https://travis-ci.org/brandonsoto/gdt.svg?branch=master)](https://travis-ci.org/brandonsoto/gdt)
[![Test Coverage](https://api.codeclimate.com/v1/badges/c203adcc92be588cf10d/test_coverage)](https://codeclimate.com/github/brandonsoto/gdt/test_coverage)

## Overview

GDT: developer script that allows you to quickly and easily debug a remote target or local core dump. It's essentially a wrapper around GDB that can automatically attach to a remote process and generate GDB's `solib-search-path` and `dir` options for you.

### Features
- Debug a remote process
- Debug a core dump
- Create a report summary for a core dump

## Configuration

On the first startup, gdt will generate config.json by asking you for certain file paths and target parameters. All subsequent uses of gdt will use config.json.

### config.json

This file will be generated when you run gdt for the first time. It can be found in gdt_files/. It contains path and target configurations. Customize it however you need to (Note: I recommend keeping the existing names in excluded_dir_names as it helps the path generation algorithm). You will find the following options:

```code
{
    "gdb_path": "GDB_PATH",                      // path to GDB executable (I highly recommend QNX's GDB 7 - "<QNX_SDK_PATH>\\host\\win64\\x86_64\\usr\\bin\\ntoarmv7-gdb.exe")
    "project_root_path": "PROJECT_ROOT",         // path to project's root directory
    "symbol_root_path": "SYMBOL_ROOT_PATH",      // path to root symbol directory
    "excluded_dir_names": ["EXCLUDED_DIR_NAME"], // names of directories to be excluded from solib/source path generating (ex. .svn, .git, .vscode, etc.)
	"target_ip": "TARGET_IP4",                   // the target's IPv4 address (default: "192.168.1.26")
    "target_user": "TARGET_USER",                // the target's username (default: "root")
    "target_password": "TARGET_PASSWORD",        // the target's password (default: "#Pasa3Ford")
    "target_debug_port": "DEBUG_PORT",           // the port to connect GDB to (default: "8000")
    "target_prompt": "TELNET_PROMPT"             // the target's command line prompt (default: "# ")
}
```

### gdbinit

This file will be generated when you run gdt for the first time. It can be found in gdt_files/. This file contains GDB commands to automatically execute during GDB startup. It includes useful routines and options I've found, but feel free to customize it however you'd like. gdt uses this file when it generates commands.txt. Here's an example of what it may look like:

> **WARNING:** this file will be overwritten when running `python gdt.py init`

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

### commands.txt

This is a file that gdt generates to pass to GDB. It can be found in gdt_files/. Any changes you make this file will be overwritten except when using the cmd gdt command-line option. Here's an example of what the file may look like:

```code
define print_qstring_dynamic
    set $d=(QStringData*)$arg0.d
    printf "(Qt5 QString)0x%x length=%i: \"",&$arg0,$d->size
    set $i=0
    while $i < $d->size
        set $c=$d->data()[$i++]
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

file D:\\Projects\\Symbols\\Multimedia\\bin\\armle-v7\\release\\MM_DioCarLifeService.full
set solib-search-path D:\\Projects\\Symbols\\VehicleServices\\dll\\armle-v7\\release;D:\\Projects\\Symbols\\VCA\\dll\\armle-v7\\release
dir D:\\Projects\\MY18.5_Baidu_Dev\\MM_DioCarLifeService\\src
target qnx 192.168.1.26:8000
attach 101181
```

The actual file will be a lot longer than this example.

### default_gdbinit

This file is used on the first startup of gdt to generate gdbinit. It can be found in gdt_files/. **DO NOT MODIFY THIS FILE.**

### core_report_commands

This file is contains gdb commands to generate a core dump report summary. It can be found in gdt_files/. Feel free to modify it if it doesn't fit your needs.

## How can I use the tool?

> Use *.full files for the (-p) command-line argument when they are available. See examples below.

### Get usage help:

```code
python gdt.py -h
python gdt.py init -h
python gdt.py remote -h
python gdt.py core -h
python gdt.py cmd -h
```

### Running gdt for the first time
Before using gdt, you will need to generate `config.json`. This can be done by running:
```code
python gdt.py init
```

### Remote Debugging a local build

1. Build the module of your choice with symbols enabled
2. Update binary on target and reboot
3. Set `projection_root_path` in `config.json` to your project's root directory (or specify -r command-line option in step 5)
4. Set `symbols_root_path` in `config.json` to your project's root directory (or specify -s command-line option in step 5)
5. Run:
```code
python gdt.py remote -p <project_root_dir>/bin/program.full
```


### Debugging a Core File from a Local Build
1. Set `projection_root_path` in `config.json` to your project's root directory (or specify -r command-line option in step 4)
2. Set `symbols_root_paths` in `config.json` to your project's root directory (or specify -s command-line option in step 4)
3. Copy core file from target to host machine
4. Run:
```code
python gdt.py core -p <project_root_dir>/Module/bin/program.full -c <project_root_dir>/bin/program.core`
```

### Generating a core dump report
gdt allows you to automatically create a core dump report. This is very useful when you need to attach core dump summaries to tickets.

1. Set `projection_root_path` in `config.json` to your project's root directory (or specify -r command-line option in step 4)
2. Set `symbols_root_paths` in `config.json` to your project's root directory (or specify -s command-line option in step 4)
3. Copy core file from target to host machine
4. Run:
```code
python gdt.py core -p <project_root_dir>/Module/bin/program.full -c <project_root_dir>/bin/program.core` -rp --report-out coredump.log
```


### Debug using a GDB Command File
```code
python gdt.py cmd Project/gdb_commands.txt
```

## Known Issues

    There is a chance that GDB will not show the correct source location when using the "frame" command. This occurs when multiple source files have the same name. The current source path algorithm does not account for this. For the time being, if this happens please run:

    dir <source_dir> // source_dir = directory of source file
