# GDT

<a href="https://codeclimate.com/github/brandonsoto/gdt/maintainability"><img src="https://api.codeclimate.com/v1/badges/c203adcc92be588cf10d/maintainability" /></a>

## What is this tool

GDT (GDB Developer Tool) - developer script to quickly and easily debug a core file or remote target

### Features include

    - Connect GDB to remote target
    - Connect GDB to a remote process
    - Connect GDB a local core file

### Prerequisites

TODO

## How can I install the tool

TODO

## How can I use the tool

### Get usage help

```shell
python gdt.py --help
python gdt.py -h
```

### Connect to remote target but no process

```shell
python gdt
```

### Debug a remote process

```shell
# use absolute path to file
python gdt -m D:/Projects/MY20/Multimedia/bin/armle-v7/release/MM_DioCarLifeService.full
python gdt --module D:/Projects/MY20/Multimedia/bin/armle-v7/release/MM_DioCarLifeService.full

# use relative path to file
python gdt -m ../MM_DioCarLifeService.full
python gdt --module ../MM_DioCarLifeService.full

```

### Debug a local core file

```shell
# use absolute paths to files
python gdt.py -m D:/Projects/Symbols/Module/bin/MM_DioCarLifeService.full -c D:/Projects/Core/MM_DioCarLifeService.core
python gdt.py --module D:/Projects/Symbols/Module/bin/MM_DioCarLifeService.full --core D:/Projects/Core/MM_DioCarLifeService.core

# using relative paths to files
python gdt.py -m Symbols/Module/bin/MM_DioCarLifeService.full -c Core/MM_DioCarLifeService.core
python gdt.py --module Symbols/Module/bin/MM_DioCarLifeService.full --core Core/MM_DioCarLifeService.core
```