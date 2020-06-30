import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import pyipttool.ipt

class Coverage:
    def __init__(self, module_name, start_address, end_address, pt_filename, dump_filename):
        self.module_name = module_name
        self.pt_filename = pt_filename
        self.dump_filename = dump_filename
        self.start_address = start_address
        self.end_address = end_address
        self.addresses = {}

        self.ptlog_analyzer = pyipttool.ipt.Analyzer(self.dump_filename,
                                        dump_symbols = False,
                                        dump_instructions = False,
                                        load_image = True,
                                        progress_report_interval = 0)

        self.ptlog_analyzer.open_ipt_log(self.pt_filename)
        #self.ptlog_analyzer.add_load_image_address_range(self.start_address, self.end_address)

    def add_block(self, offset, block):
        start_address = block['IP']
        if not start_address in self.addresses:
            self.addresses[start_address] = {}
        self.addresses[start_address][ block['EndIP']] = (offset, block)

    def save(self, output_filename):
        instruction_addresses = {}

        """
        for start_address in self.addresses.keys():
            for end_address in self.addresses[start_address].keys():
                (offset, block) = self.addresses[start_address][end_address]
                print('Dumping %x - %x (sync_offset: %x, offset: %x)' % (block['IP'], block['EndIP'], block['SyncOffset'], offset))
                for insn in self.ptlog_analyzer.enumerate_instructions(start_address = block['IP'], end_address = block['EndIP'], stop_address = block['EndIP'], sync_offset = block['SyncOffset']):
                    instruction_addresses[insn.ip] = 1

                print('len(instruction_addresses): %d' % len(instruction_addresses))
        """

        for insn in self.ptlog_analyzer.enumerate_instructions(start_address = self.start_address, end_address = self.end_address):
            instruction_addresses[insn.ip] = 1

        with open(output_filename, 'w') as fd:
            for instruction_address in instruction_addresses.keys():
                fd.write('%s+%x\n' % (module_name, instruction_address - self.start_address))

    def print(self):
        for address in self.addresses.keys():
            print('%s+%x' % (module_name, address - start_address))

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

    if args.cache_file:
        block_analyzer = pyipttool.cache.Reader(args.cache_file, args.pt_filename)

        debugger = windbgtool.debugger.DbgEngine()
        debugger.load_dump(args.dump_filename)
        debugger.enumerate_modules()

        start_address = 0
        end_address = 0

        if args.module_name:
            module_name = args.module_name
            (start_address, end_address) = debugger.get_module_range(args.module_name)
        else:
            start_address = args.start_address
            end_address = args.end_address

        coverage = Coverage(module_name, start_address, end_address, args.pt_filename, args.dump_filename)
        
        for (offset, block) in block_analyzer.enumerate_block_range(cr3 = args.cr3, start_address = start_address, end_address = end_address):
            if args.format == 'instruction':
                address = block['IP']
                symbol = debugger.find_symbol(address)
                print('> %.16x (%s) (sync_offset=%x, offset=%x)' % (address, symbol, block['SyncOffset'], offset))
                print('\t' + debugger.get_disassembly_line(address))
            elif args.format == 'modoffset_coverage':
                coverage.add_block(offset, block)

        if args.format == 'modoffset_coverage':
            if args.output_filename:
                coverage.save(args.output_filename)
            else:
                coverage.print()

    else:
        ptlog_analyzer = pyipttool.ipt.Analyzer(args.dump_filename, 
                                         dump_symbols = dump_symbols, 
                                         load_image = load_image)

        ptlog_analyzer.open_ipt_log(args.pt_filename, start_offset = args.start_offset, end_offset = args.end_offset)

        for block in ptlog_analyzer.enumerate_blocks(move_forward = False, block_offset = args.block_offset):
            print('block.ip: %.16x ~ %.16x (%.16x)' % (block.ip, block.end_ip, block.ninsn))
