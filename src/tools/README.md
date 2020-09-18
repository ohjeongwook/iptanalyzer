# IPTAnalyzer Tools

Name | Description
:--- | :----------
generate_cache.py | Generate cache files
dump_blocks.py | Dump blocks
dump_coverage.py | Dump coverage file that can be loaded by Lighthouse
dump_instructions.py | Dump instructions at specific offset
find_api_calls.py | Find API calls using symbol name

---
## generate_cache.py

```
usage: generate_cache.py [-h] [-p <PT filename>] [-d <process dump filename>] [-c <cache filename>] [-C <cr3>]
                         [-D <debug level>] [-O <debug filename>] [-t <temporary directory>] [-l <log directory>]

This is a script to generate cache file

optional arguments:
  -h, --help            show this help message and exit
  -p <PT filename>      Intel PT trace filename
  -d <process dump filename>
                        Process dump filename
  -c <cache filename>   Cache filename
  -C <cr3>              CR3 value to include (cr3 is associated with unique process)
  -D <debug level>      Debug level
  -O <debug filename>   Debug filename
  -t <temporary directory>
                        Temporary directory to save temporary cache files
  -l <log directory>    Log directory
```

---
### Example

```
python %IPTANALYZER%\tools\generate_cache.py -p artifacts\EQNEDT32.pt -d artifacts\EQNEDT32.dmp -o artifacts\blocks.sqlite -D 3
```

---
## dump_blocks.py

```
usage: dump_blocks.py [-h] [-p <PT filename>] [-d <process dump filename>] [-c <cache filename>] [-C <cr3>]
                      [-D <debug level>] [-O <debug filename>] [-s <start address>] [-e <end address>]
                      [-m <module name>] [-S <start offset>] [-E <end offset>] [-b <block offset>]

This is a tool to dump blocks

optional arguments:
  -h, --help            show this help message and exit
  -p <PT filename>      Intel PT trace filename
  -d <process dump filename>
                        Process dump filename
  -c <cache filename>   Cache filename
  -C <cr3>              CR3 value to include (cr3 is associated with unique process)
  -D <debug level>      Debug level
  -O <debug filename>   Debug filename
  -s <start address>    Start address to include
  -e <end address>      End address to include
  -m <module name>      Module name to dump
  -S <start offset>     Start offset in the file
  -E <end offset>       End offset in the file
  -b <block offset>     Block offset to dump
```

---
### Example

```
python %IPTANALYZER%\tools\dump_blocks.py -p artifacts\trace.pt -d artifacts\notepad.exe.dmp -S 0x13aba74 -E 0x13adb4f -b 0x13ada69 
```

---
## dump_coverage.py

```
usage: dump_coverage.py [-h] [-p <PT filename>] [-d <process dump filename>] [-m <module name>] [-o <output filename>]
                        [-D <debug level>] [-O <debug filename>] [-s <start address>] [-e <end address>]
                        [-c <cache filename>] [-C <cr3>]

This is a tool to generate coverage file that can be used by lighthouse

optional arguments:
  -h, --help            show this help message and exit
  -p <PT filename>      Intel PT trace filename
  -d <process dump filename>
                        Process dump filename
  -m <module name>      Module name to dump
  -o <output filename>  Output coverage filename
  -D <debug level>      Debug level
  -O <debug filename>   Debug filename
  -s <start address>    Start address to include
  -e <end address>      End address to include
  -c <cache filename>   Cache filename
  -C <cr3>              CR3 value to include (cr3 is associated with unique process)
```

---
### Example

```
python %IPTANALYZER%\tools\dump_coverage.py -O debug.log -p ..\PT\EQNEDT32.pt -d ..\ProcessMemory\EQNEDT32.dmp -C 0 -c ..\blocks.sqlite -m EQNEDT32 -O coverage.txt
```

---
## dump_instructions.py


```
usage: dump_instructions.py [-h] [-p <PT filename>] [-d <process dump filename>] [-c <cache filename>] [-C <cr3>]
                            [-D <debug level>] [-O <debug filename>] [-s <start address>] [-e <end address>]
                            [-m <module name>] [-S <start offset>] [-E <end offset>] [-o <output filename>]
                            [-i <instruction offset>]

This is a tool to dump instruction from specify pt trace file offset

optional arguments:
  -h, --help            show this help message and exit
  -p <PT filename>      Intel PT trace filename
  -d <process dump filename>
                        Process dump filename
  -c <cache filename>   Cache filename
  -C <cr3>              CR3 value to include (cr3 is associated with unique process)
  -D <debug level>      Debug level
  -O <debug filename>   Debug filename
  -s <start address>    Start address to include
  -e <end address>      End address to include
  -m <module name>      Module name to dump
  -S <start offset>     Start offset in the file
  -E <end offset>       End offset in the file
  -o <output filename>  Output filename
  -i <instruction offset>
                        Offset of instruction to dump
```

---
### Example

```
python %IPTANALYZER%\tools\dump_instructions.py -p artifacts\trace.pt -d artifacts\notepad.exe.dmp -s 0x13aba74 -e 0x13adb4f -i 0x13ada69
```

---
## find_api_calls.py

```
usage: find_api_calls.py [-h] [-p <PT filename>] [-d <process dump filename>] [-c <cache filename>] [-C <cr3>]
                         [-D <debug level>] [-O <debug filename>] [-o <output filename>] [-s <api name>]

This is a tool to find calls to APIs or functions

optional arguments:
  -h, --help            show this help message and exit
  -p <PT filename>      Intel PT trace filename
  -d <process dump filename>
                        Process dump filename
  -c <cache filename>   Cache filename
  -C <cr3>              CR3 value to include (cr3 is associated with unique process)
  -D <debug level>      Debug level
  -O <debug filename>   Debug filename
  -o <output filename>  Output filename
  -s <api name>         API Symbol in ! notation e.g. kernel32!CreateFileW
```

---
### Example

```
python %IPTANALYZER%\tools\find_api_calls.py -c artifacts\blocks.sqlite -p artifacts\trace.pt -d artifacts\notepad.exe.dmp -s "KERNELBASE!CreateFileW" -o apis_blocks.json
```
