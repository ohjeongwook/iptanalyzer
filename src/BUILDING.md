## Build Instruction

---
### libipt

* Copy libipt include files to $(SolutionDir)Libs\libipt\include
   * intel-pt.h (found under build directory: libipt\include)
* Copy libipt library files to $(SolutionDir)Libs\libipt\lib
   * libipt.dll (found under build directory: bin\Debug)
   * libipt.lib (found under build directory: lib\Debug)
   * libipt.pdb (found under build directory: bin\Debug)

---
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
