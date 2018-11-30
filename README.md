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

TO BE UPDATED
