# GDT

<a href="https://codeclimate.com/github/brandonsoto/gdt/maintainability"><img src="https://api.codeclimate.com/v1/badges/c203adcc92be588cf10d/maintainability" /></a>

## What is this tool

GDB Developer Tool (GDT) is a developer script to quickly and easily debug a core file or remote target.

## Features include

- Debug a remote target
- Debug a remote process
- Debug a local core file

## Prerequisites

- python 2.7

## Configuration

You are able to customize certain parts of GDT. All configuration can be found in gdt_config.json. You won't need to modify all options, but the paths are of particular importance. The following can be customized:

- gdb_path - the full path to the GDB executable
- project_path - the full path to the project's root directory (ex. D:/Projects/MY20)
- symbols_path - the full path to the project's symbols root directory (ex. D:/Project/Symbols)
- breakpoints - the full path to a breakpoint file to be used by GDB (empty if not used)
- excluded_dirs - names of directories to be excluded from solib path and source path generation
- target_ip - the target's IPv4 address
- target_user - the target's username
- target_password - the target's password
- target_debug_port - the port to connect GDB
- target_prompt - the target's command line prompt

## How can I install the tool

TODO

## How can I use the tool

### Get usage help

```shell
python gdt.py --help
python gdt.py -h
```

### Debug a remote process

```shell
python gdt.py -m D:/Project/bin/Service.full

# debug remote process with saved breakpoints
python gdt.py -m D:/Project/bin/Service.full -b breakpoints.txt
```

### Debug a local core file

```shell
python gdt.py -m D:/Project/bin/Service.full -c D:/Project/Core/Core.core
```

### Connect to remote target

```shell
python gdt.py
```

## Resources
- [GDB Manual](https://sourceware.org/gdb/onlinedocs/gdb/index.html#SEC_Contents)
- [The Art of Debugging with GDB, DDD, and Eclipse](https://www.amazon.com/Art-Debugging-GDB-DDD-Eclipse/dp/1593271743/ref=sr_1_2?ie=UTF8&qid=1519965502&sr=8-2&keywords=gdb&dpID=51tKpAW8vyL&preST=_SX218_BO1,204,203,200_QL40_&dpSrc=srch)


## Known Issues

TODO