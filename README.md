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
python gdt -m D:/Projects/SampleProject/bin/SampleService.full
python gdt --module D:/Projects/SampleProject/bin/SampleService.full

# use relative path to file
python gdt -m ../SampleService.full
python gdt --module ../SampleService.full

```

### Debug a local core file

```shell
# use absolute paths to files
python gdt.py -m D:/Projects/Symbols/Module/bin/SampleService.full -c D:/Projects/Core/SampleService.core
python gdt.py --module D:/Projects/Symbols/Module/bin/SampleService.full --core D:/Projects/Core/SampleService.core

# using relative paths to files
python gdt.py -m Symbols/Module/bin/SampleService.full -c Core/SampleService.core
python gdt.py --module Symbols/Module/bin/SampleService.full --core Core/SampleService.core
```