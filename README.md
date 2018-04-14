# GDT

<a href="https://codeclimate.com/github/brandonsoto/gdt/maintainability"><img src="https://api.codeclimate.com/v1/badges/c203adcc92be588cf10d/maintainability" /></a>

GDB Developer Tool (GDT) is a developer script to quickly and easily debug a core file or remote target. It's essentially a wrapper around GDB that can automatically attach to a remote process and generate GDB's "solib-search-path" and "dir" options for you.

## Features include

- Debug a remote process
- Debug a local core file

## Prerequisites

- python 2.7

## Configuration

You are able to customize certain parts of GDT. All configuration can be found in `gdt_config.json` and `gdbinit`.

### gdt_config.json
This file contains path and target configurations. The following can be customized:
- **gdb_path** - full path to the GDB executable
- **project_root_path** - path to the project's root directory
- **symbol_root_paths** - list of root symbol paths
- **excluded_dir_names** - names of directories to be excluded from solib path and source path generation (ex. .svn, .git, .vscode, etc.)
- **target_ip** - the target's IPv4 address
- **target_user** - the target's username
- **target_password** - the target's password
- **target_debug_port** - the port to connect GDB
- **target_prompt** - the target's command line prompt

### gdbinit
This file contains GDB commands to automatically execute during GDB startup. Feel free to add any custom routines or commands here.

## How can I install the tool

TODO

## How can I use the tool

### Get usage help

```shell
python gdt.py -h
python gdt.py remote -h
python gdt.py core -h
python gdt.py cmd -h
```

### Debug a remote process

```shell
python gdt.py remote -p D:/Project/bin/Service.full

# debug remote process with saved breakpoints
python gdt.py remote -b breakpoints.txt -p D:/Project/bin/Service.full

# debug remote process with symbols (symbol_root_paths in gdt_config.json will be ignored)
python gdt.py remote -p D:/Project/bin/Service.full -s D:/Project/Symbols1 D:/Project/Symbols2
```

### Debug using a GDB command file

```shell
python gdt.py cmd D:/Project/gdb_commands.txt
```

### Debug a local core file

```shell
python gdt.py core -c D:/Project/Core/Service.core -p D:/Project/bin/Service.full
```

## Resources
- [GDB Manual](https://sourceware.org/gdb/onlinedocs/gdb/index.html#SEC_Contents)
- [The Art of Debugging with GDB, DDD, and Eclipse](https://www.amazon.com/Art-Debugging-GDB-DDD-Eclipse/dp/1593271743/ref=sr_1_2?ie=UTF8&qid=1519965502&sr=8-2&keywords=gdb&dpID=51tKpAW8vyL&preST=_SX218_BO1,204,203,200_QL40_&dpSrc=srch)
- [gdbinit](http://man7.org/linux/man-pages/man5/gdbinit.5.html)


## Known Issues

TODO
