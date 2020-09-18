import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pickle
import pprint
import copy
import logging
from zipfile import ZipFile
from datetime import datetime, timedelta

import iptanalyzer.ipt
import iptanalyzer.coverage

if __name__ == '__main__':
    import argparse
    import iptanalyzer.cache
    import windbgtool.debugger
    import tools.arguments

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='This is a tool to dump blocks')
    tools.arguments.add_arguments(parser)
    tools.arguments.add_address_range_arguments(parser)
    tools.arguments.add_module_arguments(parser)
    tools.arguments.add_offset_range_arguments(parser)
    parser.add_argument('-b', dest = "block_offset", default = 0, type = auto_int, metavar = "<block offset>", help = "Block offset to dump")
    args = parser.parse_args()

    if args.dump_filename:
        dump_symbols = True
        load_image = True
    else:
        dump_symbols = False
        load_image = False

    if args.debug_level > 0:
        handlers = []
        if args.debug_filename == 'stdout':
            handlers.append(logging.StreamHandler())
        else:
            handlers.append(logging.FileHandler(args.debug_filename))

        logging.basicConfig(
            level=logging.DEBUG,
            format = '%(name)s - %(levelname)s - %(message)s',
            handlers = handlers
        )

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

    if args.cache_filename:
        block_analyzer = iptanalyzer.cache.Reader(args.cache_filename)
        coverage_logger = iptanalyzer.coverage.Logger(module_name, start_address, end_address, args.pt_filename, args.dump_filename, debugger = debugger)
        
        for (offset, address, end_address, sync_offset) in block_analyzer.enumerate_block_range(cr3 = args.cr3, start_address = start_address, end_address = end_address):
            symbol = debugger.find_symbol(address)
            print('> %.16x (%s) (sync_offset=%x, offset=%x)' % (address, symbol, sync_offset, offset))
            print('\t' + debugger.get_disassembly_line(address))
    else:
        ipt_loader = iptanalyzer.ipt.Loader(args.dump_filename, 
                                         dump_symbols = dump_symbols, 
                                         load_image = load_image,
                                         debug_level = args.debug_level)

        ipt_loader.open(args.pt_filename, start_offset = args.start_offset, end_offset = args.end_offset)
        for block in ipt_loader.decode_blocks(offset = args.block_offset, start_address = start_address, end_address = end_address):
            print('block.ip: %.16x ~ %.16x (%.16x)' % (block.ip, block.end_ip, block.ninsn))
