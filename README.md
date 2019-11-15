## Build Instruction

### libipt

* Copy libipt include files to $(SolutionDir)Libs\libipt\include
   * intel-pt.h (found under build directory: libipt\include)
* Copy libipt library files to $(SolutionDir)Libs\libipt\lib
   * libipt.dll (found under build directory: bin\Debug)
   * libipt.lib (found under build directory: lib\Debug)
   * libipt.pdb (found under build directory: bin\Debug)

### Python

* Set PYTHONHOME to the Python home directory
   * This PC -> Right Click -> Properties -> Change Settings -> Advanced -> Environment Variables -> Add/modify "PYTHONHOME" variable

```
ex) C:\Users\<user>\AppData\Local\Programs\Python\Python37
```

* [pybind11](https://pybind11.readthedocs.io/en/stable/)
   * Install pybind11 on the Python installation base

```
pip install pybind11
```

## pyptracertool

* Install capstone, windbgtool 

```
pip install capstone
pip install git+https://github.com/ohjeongwook/windbgtool
```
