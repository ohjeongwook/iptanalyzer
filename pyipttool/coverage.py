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
import capstone

class Disasm:
    def __init__(self, base_address, filename = '', image_data = b'', x64 = False):
        self.base_address = base_address
        self.image_data = b''

        if filename:
            with open(filename, 'rb') as fd:
                self.image_data = fd.read()
        elif image_data:
            self.image_data = image_data

        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if x64 else capstone.CS_MODE_32)
        
    def disassemble(self, start_address, end_address, level = 0):
        prefix = '\t' * level
        print(prefix + '* disassemble: %x - %x' % (start_address, end_address))
        start_offset = start_address - self.base_address
        instructions = []
        for i in self.md.disasm(self.image_data[start_offset:], start_address):
            print(prefix + " 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            instructions.append(i)
            if i.address == end_address:
                break

            if i.mnemonic == 'call' or i.mnemonic.startswith('j'):
                break

        return instructions

    def trace(self, start_address, end_address):
        level = 0
        instructions = []
        while 1:
            current_instructions = self.disassemble(start_address, end_address, level = level + 1)

            instructions += current_instructions
            if current_instructions[-1].address == end_address:
                break

            start_address = int(instructions[-1].op_str, 0x10)

        return instructions

class Logger:
    def __init__(self, module_name, start_address, end_address, pt_filename, dump_filename, debugger, temp_directory = os.getcwd()):
        self.module_name = module_name
        self.pt_filename = pt_filename
        self.dump_filename = dump_filename
        self.start_address = start_address
        self.end_address = end_address
        self.temp_directory = temp_directory
        self.addresses = {}

        self.ptlog_analyzer = pyipttool.ipt.Analyzer(self.dump_filename,
                                        dump_symbols = False,
                                        dump_instructions = False,
                                        load_image = True)

        self.ptlog_analyzer.open_ipt_log(self.pt_filename)

        module_filename = os.path.join(self.temp_directory, '%x.dmp' % start_address)
        region_size = end_address - start_address
        writemem_cmd = '.writemem %s %x L?%x' % (module_filename, start_address, region_size)
        debugger.run_command(writemem_cmd)
        self.disasm = Disasm(base_address = start_address, filename = module_filename)

    def add_block(self, offset, start_address, end_address, sync_offset):
        if not start_address in self.addresses:
            self.addresses[start_address] = {}
        self.addresses[start_address][end_address] = (offset, sync_offset)

    def enumerate_instructions_by_pt(self):
        sync_offsets = {}
        for start_address in self.addresses.keys():
            for end_address in self.addresses[start_address].keys():
                (offset, sync_offset) = self.addresses[start_address][end_address]
                if not sync_offset in sync_offsets:
                    sync_offsets[sync_offset] = []
                sync_offsets[sync_offset].append((start_address, end_address))

        instruction_addresses = {}
        for sync_offset, ranges in sync_offsets.items():
            logging.debug("sync_offset: %x" % sync_offset)
            for insn in self.ptlog_analyzer.decode_ranges(sync_offset = block['SyncOffset'], ranges = ranges):
                logging.debug("\tinsn.ip: %x" % insn.ip)
                instruction_addresses[insn.ip] = 1

            logging.debug('len(instruction_addresses): %d' % len(instruction_addresses))

        return instruction_addresses

    def enumerate_instruction_by_disassemble(self):
        instruction_addresses = {}
        for start_address in self.addresses.keys():
            for end_address in self.addresses[start_address].keys():
                (offset, sync_offset) = self.addresses[start_address][end_address]
                logging.debug('block: %.16x - %.16x' % (start_address, end_address))

                for instruction in self.disasm.trace(start_address, end_address):
                    instruction_addresses[instruction.address] = 1

        return instruction_addresses

    def save(self, output_filename):
        instruction_addresses= self.enumerate_instruction_by_disassemble()

        with open(output_filename, 'w') as fd:
            for address in instruction_addresses.keys():
                fd.write('%s+%x\n' % (self.module_name, address - self.start_address))

    def print(self):
        for address in self.addresses.keys():
            print('%s+%x' % (module_name, address - start_address))

if __name__ == '__main__':
    import json
    import pprint

    disasm = Disasm(base_address = 0x400000, filename = '00400000.dmp')

    address_range_list = []
    data_filename = 'tests.json'
    with open(data_filename, 'r') as fd:
        data = json.load(fd)
        for address_range in data:
            start_address = int(address_range['start'], 0x10)
            end_address = int(address_range['end'], 0x10)
            address_range_list.append((start_address, end_address))

    #address_range_list = []
    #address_range_list.append((0x41f095, 0x41ff3b))

    for (start_address, end_address) in address_range_list:
        print('%x - %x' % (start_address, end_address))
        disasm.trace(start_address, end_address)
