import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import pyipttool.ipt
import windbgtool.debugger

if __name__ == '__main__':
    import argparse
    import pyipttool.cache
    import pyipttool.dump

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-p', action = "store", default = "", dest = "pt_file")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_file")

    parser.add_argument('-s', dest = "start_address", default = 0, type = auto_int)
    parser.add_argument('-e', dest = "end_address", default = 0, type = auto_int)

    parser.add_argument('-S', dest = "start_offset", default = 0, type = auto_int)
    parser.add_argument('-E', dest = "end_offset", default = 0, type = auto_int)

    parser.add_argument('-b', dest = "block_offset", default = 0, type = auto_int)
    
    parser.add_argument('-c', action = "store", dest = "cache_file")
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int)    

    args = parser.parse_args()

    if args.dump_file:
        dump_symbols = True
        load_image = True
    else:
        dump_symbols = False
        load_image = False

    if args.cache_file:
        block_analyzer = pyipttool.cache.Reader(args.cache_file, args.pt_file)
        dump_loader = pyipttool.dump.Loader(args.dump_file)

        for (sync_offset, offset, address) in block_analyzer.enumrate_block_range(cr3 = args.cr3, start_address = args.start_address, end_address = args.end_address):
            symbol = dump_loader.get_symbol(address)
            print('> %.16x (%s) (sync_offset=%x, offset=%x)' % (address, symbol, sync_offset, offset))
            disasm_line = dump_loader.get_disassembly_line(address)
            print('\t' + disasm_line)
    else:
        ptlog_analyzer = pyipttool.ipt.LogAnalyzer(args.dump_file, 
                                         dump_symbols = dump_symbols, 
                                         load_image = load_image)

        ptlog_analyzer.open_ipt_log(args.pt_file, start_offset = args.start_offset, end_offset = args.end_offset)

        for block in ptlog_analyzer.enumerate_blocks(move_forward = False, block_offset = args.block_offset):
            print('block.ip: %.16x ~ %.16x (%.16x)' % (block.ip, block.end_ip, block.ninsn))
