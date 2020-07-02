import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta
import tempfile
import logging

import pyipttool.pyipt
import windbgtool.debugger

class Analyzer:
    def __init__(self, dump_filename = '', load_image = False, dump_instructions = False, dump_symbols = True, progress_report_interval = 0, temp_foldername = ''):
        self.progress_report_interval = progress_report_interval
        self.dump_instructions = dump_instructions
        self.dump_symbols = dump_symbols
        self.load_image = load_image
        self.load_image_ranges = []
        self.loaded_modules = {}
        self.error_locations = {}

        self.address_list = None
        self.basic_block_addresss_to_offsets = {}
        self.block_offsets_to_ips = {}
        self.psb_offsets = []

        if temp_foldername:
            self.TempFolderName = temp_foldername
        else:
            self.TempFolderName = tempfile.gettempdir()

        if dump_filename:
            self.debugger = windbgtool.debugger.DbgEngine()
            self.debugger.load_dump(dump_filename)
            self.address_list = self.debugger.get_address_list()

            if self.dump_symbols:
                self.debugger.enumerate_modules()
        else:
            self.debugger = None

    def open_ipt_log(self, pt_filename, start_offset = 0, end_offset = 0):
        self.start_offset = start_offset
        self.end_offset = end_offset

        self.loaded_modules = {}
        self.error_locations = {}

        self.ipt = pyipttool.pyipt.ipt()
        self.ipt.open(pt_filename, self.start_offset , self.end_offset)

    def __extract_ipt(self, pt_zip_filename, pt_filename ):
        if not os.path.isfile(pt_filename):
            logging.info("* Extracting test trace file:")
            with ZipFile(pt_zip_filename, 'r') as zf:
               zf.extractall()

    def __get_hex_line(self, raw_bytes):
        raw_line = ''
        for byte in raw_bytes:
            raw_line += '%.2x ' % (byte % 256)

    def add_image(self, address, use_address_map = True):
        if address in self.loaded_modules:
            return self.loaded_modules[address]

        address_info = self.debugger.get_address_info(address)
        if self.dump_symbols and address_info and 'Module Name' in address_info:
            module_name = address_info['Module Name'].split('.')[0]
            self.debugger.load_symbols([module_name, ])

        base_address = region_size = None
        if use_address_map and self.address_list:
            for mem_info in self.address_list:
                if mem_info['BaseAddr'] <= address and address < mem_info['EndAddr']:
                    base_address = mem_info['BaseAddr']
                    region_size = mem_info['RgnSize']
                    break
        
        if (base_address == None or region_size == None) and address_info:
            base_address = int(address_info['Base Address'], 16)
            region_size = int(address_info['Region Size'], 16)

        if base_address == None or region_size == None:
            logging.error('add_image failed to find base address for %x' % address)
            return False

        if base_address in self.loaded_modules:
            return self.loaded_modules[base_address]

        dump_filename = os.path.join(self.TempFolderName, '%x.dmp' % base_address)
        writemem_cmd = '.writemem %s %x L?%x' % (dump_filename, base_address, region_size)
        self.debugger.run_command(writemem_cmd)

        if not os.path.isfile(dump_filename):
            return False

        if os.path.getsize(dump_filename) < region_size:
            return False

        logging.error('add_image base_address: %.8x dump_filename: %s' % (base_address, dump_filename))
        self.ipt.add_image(base_address, dump_filename)
        self.loaded_modules[address] = True
        self.loaded_modules[base_address] = True
        return True

    # True:  Handled error
    # False: No errors or repeated and ignored error
    def handle_decode_status(self, address, decode_status):
        if decode_status == pyipttool.pyipt.pt_error_code.pte_ok:
            return False

        if decode_status == pyipttool.pyipt.pt_error_code.pte_nomap:
            if address in self.error_locations:
                return False

            self.error_locations[address] = 1

            if self.load_image:
                return self.add_image(address)

        current_offset = self.ipt.get_offset()
        print("%.8x: insn.ip: 0x%.16x decode_status: 0x%.8x" % (current_offset, ip, decode_status))
        return False 

    def is_in_load_image_range(self, address):
        if len(self.load_image_ranges) == 0:
            return True

        for (start_address, end_address) in self.load_image_ranges:
            if start_address <= address and address <= end_address:
                return True

        return False

    def add_load_image_address_range(self, start_address, end_address):
        self.load_image_ranges.append((start_address, end_address))

    def enumerate_instructions(self, instruction_offset = 0, start_address = 0, end_address = 0, stop_address = 0, sync_offset = 0):
        if sync_offset > 0:
            self.ipt.set_instruction_sync_offset(sync_offset)

        instruction_count = 0
        while 1:
            insn = self.ipt.decode_instruction()
            if not insn:
                status = self.ipt.get_status()
                decode_status = self.ipt.get_decode_status()
                break

            decode_status = self.ipt.get_decode_status()
            if decode_status == pyipttool.pyipt.pt_error_code.pte_eos:
                break

            current_offset = self.ipt.get_offset()
            if not self.handle_decode_status(insn.ip, decode_status):
                if self.progress_report_interval > 0 and instruction_count % self.progress_report_interval == 0:
                    size = self.ipt.get_size()
                    progress_offset = current_offset - self.start_offset
                    logging.info('enumerate_instructions: offset: %x progress: %x/%x (%f%%)' % (
                        current_offset,
                        progress_offset,
                        size, 
                        (progress_offset*100)/size))

                if instruction_offset > 0:
                    if instruction_offset == current_offset:
                        yield insn

                    if instruction_offset < current_offset:
                        break

                else:
                    if (start_address == 0 and end_address == 0) or start_address <= insn.ip and insn.ip <= end_address:
                        yield insn

                instruction_count += 1

                if stop_address != 0 and insn.ip == stop_address:
                    break

    def find_ranges(self, sync_offset = 0, ranges = []):
        if sync_offset > 0:
            self.ipt.set_instruction_sync_offset(sync_offset)

        stop_addresses = {}
        for (start_address, end_address) in ranges:
            stop_addresses[end_address] = 1

        while 1:
            insn = self.ipt.decode_instruction()
            if not insn:
                break

            decode_status = self.ipt.get_decode_status()
            if decode_status == pyipttool.pyipt.pt_error_code.pte_eos:
                break

            current_offset = self.ipt.get_offset()

            if not self.handle_decode_status(insn.ip, decode_status):
                for (start_address, end_address) in ranges:
                    if start_address <= insn.ip and insn.ip <= end_address:
                        if insn.ip in stop_addresses:
                            print("* Found insn.ip (%x) in stop_addresses" % insn.ip)
                            del stop_addresses[insn.ip]
                            print('\tlen(stop_addresses): %d' % len(stop_addresses))
                        yield insn
                        break

            if len(stop_addresses) == 0:
                break                    

    def record_block_offsets(self, block, cr3 = 0):
        sync_offset = self.ipt.get_sync_offset()
        offset = self.ipt.get_offset()

        logging.debug("%.8x: record_block_offsets: sync_offset: %.16x cr3: %.16x ip: %.16x" % (offset, sync_offset, cr3, block.ip))
        if not cr3 in self.basic_block_addresss_to_offsets:
            self.basic_block_addresss_to_offsets[cr3] = {}

        self.psb_offsets.append(sync_offset)
        if not block.ip in self.basic_block_addresss_to_offsets[cr3]:
            self.basic_block_addresss_to_offsets[cr3][block.ip] = {}

        if not sync_offset in self.basic_block_addresss_to_offsets[cr3][block.ip]:
            self.basic_block_addresss_to_offsets[cr3][block.ip][sync_offset]={}

        if not offset in self.basic_block_addresss_to_offsets[cr3][block.ip][sync_offset]:
            self.basic_block_addresss_to_offsets[cr3][block.ip][sync_offset][offset] = 1
        else:
            self.basic_block_addresss_to_offsets[cr3][block.ip][sync_offset][offset] += 1

        if not cr3 in self.block_offsets_to_ips:
            self.block_offsets_to_ips[cr3] = {}

        if not offset in self.block_offsets_to_ips[cr3]:
            self.block_offsets_to_ips[cr3][offset] = []

        self.block_offsets_to_ips[cr3][offset].append({'IP': block.ip, 'EndIP': block.end_ip, 'SyncOffset': sync_offset})

    def decode_blocks(self):
        self.basic_block_addresss_to_offsets = {}
        self.block_offsets_to_ips = {}
        self.psb_offsets = []

        while 1:
            block = self.ipt.decode_block()
            if not block:
                break

            skip_to_next_sync = False
            decode_status = self.ipt.get_decode_status()
            offset = self.ipt.get_offset()
            address = block.ip
            if decode_status == pyipttool.pyipt.pt_error_code.pte_ok:
                self.record_block_offsets(block, self.ipt.get_current_cr3())

            elif decode_status == pyipttool.pyipt.pt_error_code.pte_eos:
                logging.debug("%.8x: ip: %.16x decode_status(pte_eos): %x" % (offset, address, decode_status))
                break

            elif decode_status == pyipttool.pyipt.pt_error_code.pte_nomap:
                logging.debug("%.8x: ip: %.16x decode_status(pte_nomap): %x" % (offset, address, decode_status))

                skip_to_next_sync = True
                if self.load_image:
                    if self.add_image(address):
                        logging.debug("%.8x: add_image succeed for %.16x" % (offset, address))
                        skip_to_next_sync = False
                    else:
                        logging.debug("%.8x: add_image failed for %.16x" % (offset, address))

            else:
                logging.debug("%.8x: ip: %.16x decode_status: %x" % (offset, address, decode_status))
                skip_to_next_sync = True

            if skip_to_next_sync:
                if not self.ipt.forward_block_sync():
                    logging.debug("%.8x: forward_block_sync failed for %.16x" % (offset, address))
                    break

    def enumerate_sync_offsets(self):
        sync_offsets = []

        while 1:
            sync_offset = self.ipt.get_sync_offset()
            sync_offsets.append(sync_offset)

            if not self.ipt.forward_block_sync():
                break

        return sync_offsets

    def enumerate_blocks(self, log_filename = '', block_offset = 0):
        self.basic_block_addresss_to_offsets = {}
        self.block_offsets_to_ips = {}
        self.psb_offsets = []
        self.StartTime = datetime.now()
        block_count = 0
        while 1:
            block = self.ipt.decode_block()
            if not block:
                break

            decode_status = self.ipt.get_decode_status()
            if decode_status == pyipttool.pyipt.pt_error_code.pte_eos:
                break

            if not self.handle_decode_status(block.ip, decode_status):
                sync_offset = self.ipt.get_sync_offset()

                if self.progress_report_interval > 0 and block_count % self.progress_report_interval == 0:
                    time_diff = datetime.now() - self.StartTime
                    if time_diff.seconds > 0:
                        speed = block_count/time_diff.seconds
                    else:
                        speed = 0
                    size = self.ipt.get_size()
                    relative_offset = sync_offset - self.start_offset
                    logging.info('DecodeBlock: %x +%x @ %d/%d (%f%%) speed: %d blocks/sec' % (self.start_offset, block_count, relative_offset, size, (relative_offset*100)/size, speed))

                if self.dump_instructions:
                    logging.info('%x (%x): %s' % (sync_offset, offset, self.debugger.find_symbol(block.ip)))

                self.record_block_offsets(block, self.ipt.get_current_cr3())

                if block_offset > 0:
                    if block_offset == sync_offset:
                        yield block

                    if block_offset < sync_offset:
                        break

                else:
                    yield block

        block_count += 1
