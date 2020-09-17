# ipt

* What is Processor Trace for?

> It can be used to automatically triage exploits. Usually PT logs are huge and it takes long time to process them. ipt will perform multiprocessing to create cache file to be used for post-mortem analysis.

---
# Tools

* [ipt](ipt) is a thin layer upon Intel [libipt](https://github.com/intel/libipt)
* [pyipt](pyipt) is a python wrapper around ipt
   * It features multiprocessing to process large IPT logs
   * It caches major block offsets to be used in post-processing scripts
   * Some examples are under [iptanalyzer](src/iptanalyzer) folder

---
# Usage

For a good example, please read my article [Using Intel PT for Vulnerability Triaging with IPTAnalyzer](https://darungrim.com/research/2020-05-07-UsingIntelPTForVulnerabilityTriagingWithIPTAnalyzer.html)

## Decoding Blocks

```
    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-p', action = "store", default = "", dest = "pt_file")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_file")
    parser.add_argument('-c', action = "store", default="blocks.cache", dest = "cache_file")
    parser.add_argument('-t', action = "store", default=tempfile.gettempdir(), dest = "temp")
    parser.add_argument('-o', dest = "offset", default = 0, type = auto_int)
```

---
## Build Instruction

### libipt

* Copy libipt include files to $(SolutionDir)Libs\libipt\include
   * intel-pt.h (found under build directory: libipt\include)
* Copy libipt library files to $(SolutionDir)Libs\libipt\lib
   * libipt.dll (found under build directory: bin\Debug)
   * libipt.lib (found under build directory: lib\Debug)
   * libipt.pdb (found under build directory: bin\Debug)

### Setup Python Environment

1. The project depends on PYTHONEHOME environment variable to find PYTHON insntallation, set PYTHONHOME to the Python home directory

   * This PC -> Right Click -> Properties -> Change Settings -> Advanced -> Environment Variables -> Add/modify "PYTHONHOME" variable

```
ex) C:\Users\<user>\AppData\Local\Programs\Python\Python38
```

   * Or, you can use setx to set PYTHONHOME variable.
```
setx PYTHONHOME %USERPROFILE%\AppData\Local\Programs\Python\Python38
```

2. Install [pybind11](https://pybind11.readthedocs.io/en/stable/)

```
pip install pybind11
```

#### Package dependencies

* Install pykd, capstone, windbgtool

```
pip install pykd
pip install capstone
pip install git+https://github.com/ohjeongwook/windbgtool
```

* Install WinDbg from [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk)

---
## Fix Windbg DLL Compatibility Issues

PyKD sometimes suffers from WinDbg DLL compability issues. Please run script from [fix_windbg_files.py](https://github.com/ohjeongwook/windbgtool/blob/master/pykdfix/fix_windbg_files.py) when you find the issue affecting PyKD loading.
