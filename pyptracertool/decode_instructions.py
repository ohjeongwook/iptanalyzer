import os
import sys
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import capstone

import decoder
import windbgtool.debugger

if __name__ == '__main__':
    cache_folder = 'Tmp'
    pt_filename = '../TestFiles/trace.pt'
    dump_filename = '../TestFiles/notepad.exe.dmp'
    start_offset = 0x13aba74
    end_offset = start_offset + 0x20cd + 10

    pytracer = decoder.PTLogAnalyzer(pt_filename,
                                     dump_filename,
                                     dump_symbols = False,
                                     dump_instructions = False,
                                     load_image = True,
                                     start_offset = start_offset,
                                     end_offset = end_offset,
                                     disassembler = "windbg")

    for insn in pytracer.DecodeInstruction(move_forward = False, instruction_offset = 0x13ada69):
        disasmline = pytracer.GetDisasmLine(insn)
        print('Instruction: %s' % (disasmline))
