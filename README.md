# GDT

<a href="https://codeclimate.com/github/brandonsoto/gdt/maintainability"><img src="https://api.codeclimate.com/v1/badges/c203adcc92be588cf10d/maintainability" /></a>

## What is this tool

GDT (GDB Developer Tool) - developer script to quickly and easily debug a core file or remote target

### Features include

- Connect GDB to remote target
- Connect GDB to a remote process
- Connect GDB a local core file

### Prerequisites

- python 2.7

## How can I install the tool

TODO

## How can I use the tool

### Get usage help

```shell
python gdt.py --help
python gdt.py -h
```

### Connect to remote target

```shell
python gdt.py
```

### Debug a remote process

```shell
python gdt.py -m D:/Project/bin/Service.full

# debug remote process with saved breakpoints
python gdt.py -m D:/Project/bin/Service.full -b breakpoints.txt
```

### Debug a local core file

```shell
python gdt.py -m D:/Project/bin/SampleService.full -c D:/Project/Core/Core.core
```