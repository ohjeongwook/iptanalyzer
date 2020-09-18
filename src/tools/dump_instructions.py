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
    import tools.arguments

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='This is a tool to dump instruction from specify pt trace file offset')
    tools.arguments.add_arguments(parser)
    tools.arguments.add_address_range_arguments(parser)
    tools.arguments.add_module_arguments(parser)
    tools.arguments.add_offset_range_arguments(parser)
    parser.add_argument('-o', action = "store", dest = "output_filename", default = "output.log", metavar = "<output filename>", help = "Output filename")
    parser.add_argument('-i', dest = "instruction_offset", default = 0, type = auto_int, metavar = "<instruction offset>", help = "Offset of instruction to dump")
    args = parser.parse_args()

    debugger = windbgtool.debugger.DbgEngine()
    debugger.load_dump(args.dump_filename)
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

    ipt_loader = iptanalyzer.ipt.Loader(args.dump_filename,
                                     dump_symbols = False,
                                     dump_instructions = False,
                                     load_image = True)

    ipt_loader.open(args.pt_file, start_offset = args.start_offset, end_offset = args.end_offset)

    for insn in ipt_loader.decode_instructions(offset = args.instruction_offset, start_address = start_address, end_address = end_address):
        try:
            disasmline = debugger.get_disassembly_line(insn.ip)
            print('Instruction: %s' % (disasmline))
        except:
            traceback.print_exc()
