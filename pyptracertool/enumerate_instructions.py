import os
import sys
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import decoder
import windbgtool.debugger

if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-p', action = "store", default = "", dest = "pt")
    parser.add_argument('-d', action = "store", default = "", dest = "dump")

    parser.add_argument('-s', dest = "start_address", default = 0, type = auto_int)
    parser.add_argument('-e', dest = "end_address", default = 0, type = auto_int)

    parser.add_argument('-S', dest = "start_offset", default = 0, type = auto_int)
    parser.add_argument('-E', dest = "end_offset", default = 0, type = auto_int)

    parser.add_argument('-i', dest = "instruction_offset", default = 0, type = auto_int)

    args = parser.parse_args()

    dump_loader = dump.Loader(args.dump)
    ptlog_analyzer = decoder.PTLogAnalyzer(args.dump,
                                     dump_symbols = False,
                                     dump_instructions = False,
                                     load_image = True,
                                     progress_report_interval = 0)

    ptlog_analyzer.OpenPTLog(args.pt, start_offset = args.start_offset, end_offset = args.end_offset)
    for insn in ptlog_analyzer.EnumerateInstructions(move_forward = False, instruction_offset = args.instruction_offset, start_address = args.start_address, end_address = args.end_address):
        disasmline = dump_loader.GetDisasmLine(insn)
        print('Instruction: %s' % (disasmline))
