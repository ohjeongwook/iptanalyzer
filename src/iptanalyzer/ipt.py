import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta
import tempfile
import logging

import iptdecoder.pyipt
import windbgtool.debugger

class Filter:
    def __init__(self, offset = 0, start_address = 0, end_address = 0, stop_address = 0, sync_offset = 0):
        self.offset = 0
        self.start_address = 0
        self.end_address = 0
        self.stop_address = 0
        self.sync_offset = 0

class Analyzer:
    def __init__(self, dump_filename = '', load_image = False, dump_instructions = False, dump_symbols = True, temp_directory = '', debug_level = 0):     
        self.debug_level = debug_level
        self.dump_instructions = dump_instructions
        self.dump_symbols = dump_symbols
        self.load_image = load_image
        self.load_image_ranges = []
        self.loaded_modules = {}
        self.no_map_addresses = {}

        self.address_list = None
        self.psb_offsets = []
        self.records = []

        if temp_directory:
            self.temp_directory = temp_directory
        else:
            self.temp_directory = tempfile.gettempdir()

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
        self.no_map_addresses = {}

        self.ipt = iptdecoder.pyipt.ipt()
        self.ipt.open(pt_filename, self.start_offset , self.end_offset)

    def close(self):
        self.debugger.close_dump()

    def __extract_ipt(self, pt_zip_filename, pt_filename ):
        if not os.path.isfile(pt_filename):
            logging.info("* Extracting test trace file:")
            with ZipFile(pt_zip_filename, 'r') as zf:
               zf.extractall()

    def __get_hex_line(self, raw_bytes):
        raw_line = ''
        for byte in raw_bytes:
            raw_line += '%.2x ' % (byte % 256)
        
    def dump_memory(self, base_address, region_size):
        dump_filename = os.path.join(self.temp_directory, '%x.dmp' % base_address)
        writemem_cmd = '.writemem %s %x L?%x' % (dump_filename, base_address, region_size)
        self.debugger.run_command(writemem_cmd)

        if not os.path.isfile(dump_filename):
            logging.error('dump_memory failed: dump_filename (%s) does not exists' % dump_filename)
            return (0, '')

        dump_file_size = os.path.getsize(dump_filename)
        if dump_file_size < region_size:
            logging.error('dump_memory failed: dump_filename (%s) is too short (%x vs %x)' % (dump_filename, os.path.getsize(dump_filename), region_size))
            region_size = dump_file_size

        return (region_size, dump_filename)

    def add_image(self, address, use_address_map = True, load_module_image = True):
        if address in self.no_map_addresses:
            return False

        range_list = []
        if load_module_image:
            if use_address_map and self.address_list:
                for mem_info in self.address_list:
                    if mem_info['BaseAddr'] <= address and address < mem_info['EndAddr']:
                        range_list.append((mem_info['BaseAddr'], mem_info['RgnSize']))
                        logging.debug('add_image mem_info: %s' % (pprint.pformat(mem_info)))
                        break

            if len(range_list) == 0:
                address_info = self.debugger.get_address_info(address)
                if address_info:
                    if self.dump_symbols and 'Module Name' in address_info:
                        module_name = address_info['Module Name'].split('.')[0]
                        self.debugger.load_symbols([module_name, ])

                    range_list.append((int(address_info['Base Address'], 16), int(address_info['Region Size'], 16))) 

        if len(range_list) == 0:
            range_list.append((address & 0xFFFFFFFFFFFFF000, 0x1000))
            range_list.append((address & 0xFFFFFFFFFFFFFF00, 0x100))
            range_list.append((address & 0xFFFFFFFFFFFFFFF0, 0x10))

        for (base_address, region_size) in range_list:
            if self.debug_level > 1:
                logging.debug('add_image address: try to dump base_address: %.8x region_size: %x' % (base_address, region_size))

            if base_address in self.loaded_modules:
                loaded_region_size = self.loaded_modules[base_address]
                if base_address + loaded_region_size > address:
                    logging.debug('add_image cached base_address: %.8x loaded_region_size: %x' % (base_address, loaded_region_size))
                    return True

            (loaded_region_size, dump_filename) = self.dump_memory(base_address, region_size)
            if loaded_region_size != 0 and address < base_address + loaded_region_size:
                region_size = loaded_region_size
                break

        if base_address + region_size <= address:
            self.no_map_addresses[address] = True
            return False

        if self.debug_level > 1:
            logging.debug('add_image base_address: %.8x region_size: %x' % (base_address, region_size))

        self.ipt.add_image(base_address, dump_filename)
        self.loaded_modules[address] = region_size
        self.loaded_modules[base_address] = region_size
        return True

    def is_in_load_image_range(self, address):
        if len(self.load_image_ranges) == 0:
            return True

        for (start_address, end_address) in self.load_image_ranges:
            if start_address <= address and address <= end_address:
                return True

        return False

    def add_load_image_address_range(self, start_address, end_address):
        self.load_image_ranges.append((start_address, end_address))

    def enumerate_sync_offsets(self):
        sync_offsets = []

        while 1:
            sync_offset = self.ipt.get_sync_offset()
            sync_offsets.append(sync_offset)

            if not self.ipt.forward_block_sync():
                break

        return sync_offsets

    def decode(self, decode_type = 'block', callback = None):
        if decode_type == 'block':
            self.records = []
            self.psb_offsets = []

        pt_no_map_error_counts = {}
        while 1:
            if decode_type == 'block':
                decoded_obj = self.ipt.decode_block()
                if not decoded_obj:
                    break

                end_address = decoded_obj.end_ip
            else:
                decoded_obj = self.ipt.decode_instruction()
                if not decoded_obj:
                    break

                end_address = decoded_obj.ip

            if not decoded_obj:
                break

            address = decoded_obj.ip
            skip_to_next_sync = False
            decode_status = self.ipt.get_decode_status()
            offset = self.ipt.get_offset()

            if decode_status == iptdecoder.pyipt.pt_error_code.pte_ok or decode_status == iptdecoder.pyipt.pt_error_code.pte_bad_insn:
                if decode_status != iptdecoder.pyipt.pt_error_code.pte_ok:
                    logging.error("%.8x: ip: %.16x decode_status: %x (continue)" % (offset, address, decode_status))

                if self.debug_level > 2:
                    sync_offset = self.ipt.get_sync_offset()
                    logging.debug("%.8x: decode: sync_offset: %.16x ip: %.16x" % (offset, sync_offset, address))
                    
                if callback:
                    callback(decoded_obj)
                else:
                    return decoded_obj

            elif decode_status == iptdecoder.pyipt.pt_error_code.pte_eos:
                logging.debug("%.8x: ip: %.16x decode_status(pte_eos): %x" % (offset, address, decode_status))
                break

            elif decode_status == iptdecoder.pyipt.pt_error_code.pte_nomap:
                if self.debug_level > 1:
                    logging.debug("%.8x: ip: %.16x decode_status(pte_nomap): %x" % (offset, address, decode_status))

                if not address in pt_no_map_error_counts:
                    pt_no_map_error_counts[address] = 1
                else:
                    pt_no_map_error_counts[address] += 1

                skip_to_next_sync = True
                
                if pt_no_map_error_counts[address] > 1:
                    logging.error("%.8x: add_image failed %d times for %.16x" % (offset, pt_no_map_error_counts[address], address))
                elif self.load_image:
                    if self.add_image(address):
                        if self.debug_level > 1:
                            logging.debug("%.8x: add_image succeed for %.16x" % (offset, address))
                        skip_to_next_sync = False
                    else:
                        if self.debug_level > 1:
                            logging.debug("%.8x: add_image failed for %.16x" % (offset, address))
            else:
                logging.error("%.8x: ip: %.16x decode_status: %x" % (offset, address, decode_status))
                skip_to_next_sync = True

            if skip_to_next_sync:
                logging.debug("%.8x: forward_block_sync @%.16x" % (offset, address))
                if not self.ipt.forward_block_sync():
                    logging.debug("%.8x: forward_block_sync failed for %.16x" % (offset, address))
                    break
        return None

    def record_block_offset(self, block):
        address = block.ip
        block_end_address = block.end_ip
        cr3 = self.ipt.get_current_cr3()
        sync_offset = self.ipt.get_sync_offset()
        offset = self.ipt.get_offset()

        if self.debug_level > 1:
            logging.debug("%.8x: record_block_offsets: sync_offset: %.16x cr3: %.16x ip: %.16x" % (offset, sync_offset, cr3, address))

        self.records.append({'IP': address, 'EndIP': block_end_address, 'SyncOffset': sync_offset, 'Offset': offset, 'CR3': cr3})

    def record_block_offsets(self):
        self.decode(decode_type = 'block', callback = self.record_block_offset)

    def decode_blocks(self, offset = 0, start_address = 0, end_address = 0):
        while 1:
            block = self.decode(decode_type = 'block')
            if not block:
                break

            current_offset = self.ipt.get_offset()

            if offset > 0:
                if offset == current_offset:
                    yield block
                elif offset < current_offset:
                    break
            else:
                if (start_address == 0 and end_address == 0) or start_address <= block.ip and block.ip <= end_address:
                    yield block

    def decode_instructions(self, offset = 0, start_address = 0, end_address = 0, stop_address = 0):
        while 1:
            instruction = self.decode(decode_type = 'instruction')
            if not instruction:
                break

            current_offset = self.ipt.get_offset()
            if offset > 0:
                if offset == current_offset:
                    yield instruction

                if offset < current_offset:
                    break
            else:
                if (start_address == 0 and end_address == 0) or start_address <= instruction.ip and instruction.ip <= end_address:
                    yield instruction

            if stop_address != 0 and instruction.ip == stop_address:
                break

    def decode_ranges(self, sync_offset = 0, ranges = []):
        if sync_offset > 0:
            self.ipt.set_instruction_sync_offset(sync_offset)

        stop_addresses = {}
        for (start_address, end_address) in ranges:
            stop_addresses[end_address] = 1

        while 1:
            instruction = self.decode(decode_type = 'instruction')
            if not instruction:
                break

            current_offset = self.ipt.get_offset()
            current_sync_offset = self.ipt.get_sync_offset()

            for (start_address, end_address) in ranges:
                if start_address <= instruction.ip and instruction.ip <= end_address:
                    logging.debug('%.16x: instruction.ip: %.16x' % (current_offset, instruction.ip))
                    if instruction.ip in stop_addresses:
                        logging.debug("* Found instruction.ip (%x) in stop_addresses" % instruction.ip)
                        del stop_addresses[instruction.ip]
                        logging.debug('\tlen(stop_addresses): %d' % len(stop_addresses))

                    yield instruction
                    break

            if len(stop_addresses) == 0:
                break

            if current_sync_offset > sync_offset:
                break
