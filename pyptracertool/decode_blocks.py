import sys
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import capstone

import pyptracertool
import windbgtool.debugger

if __name__ == '__main__':
    cache_folder = 'Tmp'
    pt_filename = '../TestFiles/trace.pt'
    dump_filename = '../TestFiles/notepad.exe.dmp'
    start_offset = 0x1c
    end_offset = start_offset + 1024*2

    pytracer = pyptracertool.Decoder(pt_filename, 
                                     dump_filename, 
                                     dump_symbols = True, 
                                     load_image = True, 
                                     start_offset = start_offset,
                                     end_offset = end_offset)
    pytracer.DecodeBlock()

