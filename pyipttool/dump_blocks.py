import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pickle
import pprint
import copy
import logging
from zipfile import ZipFile
from datetime import datetime, timedelta

import pyipttool.ipt
import pyipttool.coverage

if __name__ == '__main__':
    import argparse
    import pyipttool.cache
    import windbgtool.debugger

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-p', action = "store", default = "", dest = "pt_filename")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_filename")

    parser.add_argument('-m', action = "store", dest = "module_name", default = "")
    parser.add_argument('-o', action = "store", dest = "output_filename", default = "output.log")
    parser.add_argument('-D', action = "store", dest = "debug_filename", default = "")
    parser.add_argument('-f', action = "store", dest = "format", default = "instruction")

    parser.add_argument('-s', dest = "start_address", default = 0, type = auto_int)
    parser.add_argument('-e', dest = "end_address", default = 0, type = auto_int)

    parser.add_argument('-S', dest = "start_offset", default = 0, type = auto_int)
    parser.add_argument('-E', dest = "end_offset", default = 0, type = auto_int)

    parser.add_argument('-b', dest = "block_offset", default = 0, type = auto_int)
    
    parser.add_argument('-c', action = "store", dest = "cache_file")
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int)    

    args = parser.parse_args()

    if args.dump_filename:
        dump_symbols = True
        load_image = True
    else:
        dump_symbols = False
        load_image = False

    if args.debug_filename:
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

    if args.cache_file:
        block_analyzer = pyipttool.cache.Reader(args.cache_file)

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

        coverage_logger = pyipttool.coverage.Logger(module_name, start_address, end_address, args.pt_filename, args.dump_filename, debugger = debugger)
        
        for (offset, address, end_address, sync_offset) in block_analyzer.enumerate_block_range(cr3 = args.cr3, start_address = start_address, end_address = end_address):
            if args.format == 'instruction':
                symbol = debugger.find_symbol(address)
                print('> %.16x (%s) (sync_offset=%x, offset=%x)' % (address, symbol, sync_offset, offset))
                print('\t' + debugger.get_disassembly_line(address))
            elif args.format == 'modoffset_coverage':
                coverage_logger.add_block(offset, address, end_address, sync_offset)

        if args.format == 'modoffset_coverage':
            if args.output_filename:
                coverage_logger.save(args.output_filename)
            else:
                coverage_logger.print()

    else:
        ptlog_analyzer = pyipttool.ipt.Analyzer(args.dump_filename, 
                                         dump_symbols = dump_symbols, 
                                         load_image = load_image)

        ptlog_analyzer.open_ipt_log(args.pt_filename, start_offset = args.start_offset, end_offset = args.end_offset)
        for block in ptlog_analyzer.decode_blocks(offset = args.block_offset, start_address = start_address, end_address = end_address):
            print('block.ip: %.16x ~ %.16x (%.16x)' % (block.ip, block.end_ip, block.ninsn))
