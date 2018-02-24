# GDT

<a href="https://codeclimate.com/github/brandonsoto/gdt/maintainability"><img src="https://api.codeclimate.com/v1/badges/c203adcc92be588cf10d/maintainability" /></a>

:bug: GDB Developer Tool: developer script to quickly and easily debug a remote QNX target or core file

## Example Usages

```shell
# debug Module on the remote target
python gdt.py -m D:/Projects/Symbols/Module/bin/Module.full

# debug Module's core dump
python gdt.py -m D:/Projects/Symbols/Module/bin/Module.full -c D:/Projects/Core/Module.core
```
