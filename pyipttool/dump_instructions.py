import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import pyipttool.ipt
import windbgtool.debugger
import pyipttool.dump

if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-p', action = "store", default = "", dest = "pt_file")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_file")

    parser.add_argument('-s', dest = "start_address", default = 0, type = auto_int)
    parser.add_argument('-e', dest = "end_address", default = 0, type = auto_int)

    parser.add_argument('-S', dest = "start_offset", default = 0, type = auto_int)
    parser.add_argument('-E', dest = "end_offset", default = 0, type = auto_int)

    parser.add_argument('-i', dest = "instruction_offset", default = 0, type = auto_int)

    args = parser.parse_args()

    dump_loader = pyipttool.dump.Loader(args.dump_file)
    ptlog_analyzer = pyipttool.ipt.Analyzer(args.dump_file,
                                     dump_symbols = False,
                                     dump_instructions = False,
                                     load_image = True,
                                     progress_report_interval = 0)

    ptlog_analyzer.open_ipt_log(args.pt_file, start_offset = args.start_offset, end_offset = args.end_offset)
    for insn in ptlog_analyzer.enumerate_instructions(move_forward = False, instruction_offset = args.instruction_offset, start_address = args.start_address, end_address = args.end_address):
        try:
           disasmline = dump_loader.get_disassembly_line(insn.ip)
           print('Instruction: %s' % (disasmline))
        except:
           pass
