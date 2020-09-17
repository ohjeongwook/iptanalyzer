import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pickle
import pprint
import traceback
from zipfile import ZipFile
from datetime import datetime, timedelta

import iptanalyzer.ipt

if __name__ == '__main__':
    import argparse
    import windbgtool.debugger

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-p', action = "store", default = "", dest = "pt_file")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_file")

    parser.add_argument('-m', action = "store", dest = "module_name", default = "")
    parser.add_argument('-o', action = "store", dest = "output_filename", default = "output.log")
    parser.add_argument('-f', action = "store", dest = "format", default = "instruction")

    parser.add_argument('-s', dest = "start_address", default = 0, type = auto_int)
    parser.add_argument('-e', dest = "end_address", default = 0, type = auto_int)

    parser.add_argument('-S', dest = "start_offset", default = 0, type = auto_int)
    parser.add_argument('-E', dest = "end_offset", default = 0, type = auto_int)

    parser.add_argument('-i', dest = "instruction_offset", default = 0, type = auto_int)

    args = parser.parse_args()

    debugger = windbgtool.debugger.DbgEngine()
    debugger.load_dump(args.dump_file)
    debugger.enumerate_modules()

    start_address = 0
    end_address = 0

    if args.module_name:
        module_name = args.module_name
        (start_address, end_address) = debugger.get_module_range(args.module_name)
    else:
        module_name = ''
        start_address = args.start_address
        end_address = args.end_address

    ptlog_analyzer = iptanalyzer.ipt.Analyzer(args.dump_file,
                                     dump_symbols = False,
                                     dump_instructions = False,
                                     load_image = True)

    ptlog_analyzer.open_ipt_log(args.pt_file, start_offset = args.start_offset, end_offset = args.end_offset)

    for insn in ptlog_analyzer.decode_instructions(offset = args.instruction_offset, start_address = start_address, end_address = end_address):
        try:
            disasmline = debugger.get_disassembly_line(insn.ip)
            print('Instruction: %s' % (disasmline))
        except:
            traceback.print_exc()
