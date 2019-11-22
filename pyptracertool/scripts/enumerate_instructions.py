import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import pyptracertool.ipt
import windbgtool.debugger
import pyptracertool.dump

if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-p', action = "store", default = "", dest = "pt_file")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_file")

    parser.add_argument('-s', dest = "start_address", default = 0, type = auto_int)
    parser.add_argument('-e', dest = "end_address", default = 0, type = auto_int)

    parser.add_argument('-S', dest = "start_offset", default = 0, type = auto_int)
    parser.add_argument('-E', dest = "end_offset", default = 0, type = auto_int)

    parser.add_argument('-i', dest = "instruction_offset", default = 0, type = auto_int)

    args = parser.parse_args()

    dump_loader = pyptracertool.dump.Loader(args.dump_file)
    ptlog_analyzer = pyptracertool.ipt.LogAnalyzer(args.dump_file,
                                     dump_symbols = False,
                                     dump_instructions = False,
                                     load_image = True,
                                     progress_report_interval = 0)

    ptlog_analyzer.OpenPTLog(args.pt_file, start_offset = args.start_offset, end_offset = args.end_offset)
    for insn in ptlog_analyzer.EnumerateInstructions(move_forward = False, instruction_offset = args.instruction_offset, start_address = args.start_address, end_address = args.end_address):
        disasmline = dump_loader.GetDisasmLine(insn.ip)
        print('Instruction: %s' % (disasmline))
