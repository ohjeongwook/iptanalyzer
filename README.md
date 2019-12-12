# iptanalyzer

* [iptanalyzer](iptanalyzer) is a thin layer upon Intel [libipt](https://github.com/intel/libipt)
* [pyiptanalyzer](pyiptanalyzer) is a python wrapper around iptanalyzer
   * It features multiprocessing to process large IPT logs
   * It caches major block offsets to be used in post-processing scripts
   * Some examples are under [pyiptanalyzertool](pyiptanalyzertool) folder

## Build Instruction

### libipt

* Copy libipt include files to $(SolutionDir)Libs\libipt\include
   * intel-pt.h (found under build directory: libipt\include)
* Copy libipt library files to $(SolutionDir)Libs\libipt\lib
   * libipt.dll (found under build directory: bin\Debug)
   * libipt.lib (found under build directory: lib\Debug)
   * libipt.pdb (found under build directory: bin\Debug)

### Python Environment

1. The project depends on PYTHONEHOME environment variable to find PYTHON insntallation, set IPTANALYZER_PYTHONHOME to the Python home directory

   * This PC -> Right Click -> Properties -> Change Settings -> Advanced -> Environment Variables -> Add/modify "IPTANALYZER_PYTHONHOME" variable

```
ex) C:\Users\<user>\AppData\Local\Programs\Python\Python38
```

   * Or, you can use setx to set IPTANALYZER_PYTHONHOME variable.
```
setx IPTANALYZER_PYTHONHOME %USERPROFILE%\AppData\Local\Programs\Python\Python38
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

Please run script from [install_windbg_files.py](https://raw.githubusercontent.com/ohjeongwook/windbgtool/master/installation/install_windbg_files.py) to fix PyKD WinDbg DLL compatibility issues
