# ipt

* What is Processor Trace for?

> It can be used to automatically triage exploits. Usually PT logs are huge and it takes long time to process them. ipt will perform multiprocessing to create cache file to be used for post-mortem analysis.

---
# Tools

Name | Description
:--- | :----------
[iptdecoder](src/iptdecoder) | [libipt](https://github.com/intel/libipt) wrapper class
[pyipt](src/pyipt) | python wrapper upon iptdecoder and libipt
[iptanalyzer](src/iptanalyzer) | python library to decode ipt using libipt and process dump image extraction
[tools](src/tools) | various tools based upon iptanalyzer

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


---
# Usage

For a good example, please read my article [Using Intel PT for Vulnerability Triaging with IPTAnalyzer](https://darungrim.com/research/2020-05-07-UsingIntelPTForVulnerabilityTriagingWithIPTAnalyzer.html)
