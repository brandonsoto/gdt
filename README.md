# GDT

:bug: GDB Developer Tool: developer script to quickly and easily debug a remote QNX target or core file

## Example Usages

```shell
# debug Module on the remote target
python gdt.py -m D:/Projects/Symbols/Module/bin/Module.full

# debug Module's core dump
python gdt.py -m D:/Projects/Symbols/Module/bin/Module.full -c D:/Projects/Core/Module.core
```