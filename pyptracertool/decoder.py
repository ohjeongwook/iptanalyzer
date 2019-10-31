import os
import sys
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import capstone

import pyptracer
import windbgtool.debugger

class PTLogAnalyzer:
    def __init__(self, pt_filename, dump_filename = '', start_offset = 0, end_offset = 0, load_image = False, dump_instructions = False, dump_symbols = True, disassembler = "capstone"):
        self.StartOffset = start_offset
        self.EndOffset = end_offset
        self.DumpInstructions = dump_instructions
        self.DumpSymbols = dump_symbols
        self.LoadImage = load_image
        self.Disassembler = disassembler
        self.LoadedMemories = {}
        self.AddressToSymbols = {}
        self.BlockIPMap = {}

        if dump_filename:
            self.Debugger = windbgtool.debugger.DbgEngine()
            self.Debugger.LoadDump(dump_filename)
            self.AddressList = self.Debugger.GetAddressList()

            if dump_symbols:
                self.Debugger.EnumerateModules()

        self.PyTracer = pyptracer.PTracer()
        self.PyTracer.Open(pt_filename, start_offset, end_offset)

    def _ExtractTracePT(self, pt_zip_filename, pt_filename ):
        if not os.path.isfile(pt_filename):
            print("* Extracting test trace file:")
            with ZipFile(pt_zip_filename, 'r') as zf:
               zf.extractall()

    def _GetHexLine(self, raw_bytes):
        raw_line = ''
        for byte in raw_bytes:
            raw_line += '%.2x ' % (byte % 256)

    def LoadImageFile(self, ip, use_address_map = True):
        if ip in self.LoadedMemories:
            return self.LoadedMemories[ip]

        self.LoadedMemories[ip] = False

        address_info = self.Debugger.GetAddressInfo(ip)
        if self.DumpSymbols and address_info and 'Module Name' in address_info:
            for (address, symbol) in self.Debugger.EnumerateModuleSymbols([address_info['Module Name'], ]).items():
                self.AddressToSymbols[address] = symbol

        base_address = region_size = None

        if use_address_map:
            for mem_info in self.AddressList:
                if mem_info['BaseAddr'] <= ip and ip <= mem_info['EndAddr']:
                    base_address = mem_info['BaseAddr']
                    region_size = mem_info['RgnSize']
                    break
        else:
            base_address = int(address_info['Base Address'], 16)
            region_size = int(address_info['Region Size'], 16)

        if base_address == None or region_size == None:
            return False

        if base_address in self.LoadedMemories:
            return self.LoadedMemories[base_address]

        self.LoadedMemories[base_address] = False

        dump_filename = '%x.dmp' % base_address
        self.Debugger.RunCmd('.writemem %s %x L?%x' % (dump_filename, base_address, region_size))
        self.PyTracer.AddImage(base_address, dump_filename)
        self.LoadedMemories[ip] = True
        self.LoadedMemories[base_address] = True

        return True

    def GetCapstoneDisasmLine(self, ip, raw_bytes = ''):
        symbol = ''
        if ip in self.AddressToSymbols:
            symbol = self.AddressToSymbols[ip]

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        if raw_bytes:
            for disas in md.disasm(bytearray(raw_bytes), ip):
                return '%s (%x): %s %s' % (symbol, disas.address, disas.mnemonic, disas.op_str)
        else:
            try:
                disasmline = self.Debugger.RunCmd('u %x L1' % (ip))
                return disasmline
            except:
                pass

        return ''

    def GetDisasmLine(self, insn):
        offset = self.PyTracer.GetOffset()
        if self.Disassembler == "capstone":
            return self.GetCapstoneDisasmLine(insn.ip, insn.GetRawBytes())
        elif self.Disassembler == "windbg":
            return self.Debugger.RunCmd('u %x L1' % (insn.ip))

        return ''

    def DecodeInstruction(self, move_forward = True):
        instruction_count = 0
        while 1:
            insn = self.PyTracer.DecodeInstruction(move_forward)
            if not insn:
                break

            if instruction_count % 1000 == 0:
                offset = self.PyTracer.GetOffset()
                size = self.PyTracer.GetSize()
                print('DecodeInstruction: %x + %x @ %d/%d (%f%%)' % (self.StartOffset, instruction_count, offset, size, (offset*100)/size))

            if self.DumpInstructions or (self.DumpSymbols and insn.ip in self.AddressToSymbols):
                offset = self.PyTracer.GetOffset()
                disasmline = self.GetDisasmLine(insn)
                print('%x: %s' % (offset, disasmline))

            errcode = self.PyTracer.GetDecodeStatus()
            if errcode != pyptracer.pt_error_code.pte_ok:
                if errcode == pyptracer.pt_error_code.pte_nomap:
                    if self.LoadImageFile(insn.ip):
                        move_forward = False
                        continue
                    else:
                        disasmline = self.GetDisasmLine(insn.ip)
                        print('\t%s errorcode= %s' % (disasmline, errcode))

            instruction_count += 1
            move_forward = True

    def RecordBlockOffsets(self):
        sync_offset = self.PyTracer.GetSyncOffset()
        offset = self.PyTracer.GetOffset()

        self.BlockSyncOffsets.append(sync_offset)
        if not block.ip in self.BlockIPMap:
            self.BlockIPMap[block.ip] = {}

        if not sync_offset in self.BlockIPMap[block.ip]:
            self.BlockIPMap[block.ip][sync_offset]={}

        if not offset in self.BlockIPMap[block.ip][sync_offset]:
            self.BlockIPMap[block.ip][sync_offset][offset] = 1
        else:
            self.BlockIPMap[block.ip][sync_offset][offset] += 1

        if self.DumpInstructions or (self.DumpSymbols and block.ip in self.AddressToSymbols):
            print('%x (%x): %s' % (sync_offset, offset, self.AddressToSymbols[block.ip]))

        instruction_count += block.ninsn
        if block_count % 1000 == 0:
            time_diff = datetime.now() - self.StartTime
            if time_diff.seconds > 0:
                speed = block_count/time_diff.seconds
            else:
                speed = 0

            size = self.PyTracer.GetSize()
            relative_offset = sync_offset - self.StartOffset
            print('DecodeBlock: %x +%x @ %d/%d (%f%%) speed: %d blocks/sec' % (self.StartOffset, block_count, relative_offset, size, (relative_offset*100)/size, speed))

    def DecodeBlock(self, log_filename = '', move_forward = True):
        load_image = False
        block_count = 0
        instruction_count = 0
        error_count = {}
        self.BlockIPMap = {}
        self.BlockSyncOffsets = []

        self.StartTime = datetime.now()
        while 1:
            block = self.PyTracer.DecodeBlock(move_forward)
            if not block:
                break

            self.RecordBlockOffsets()               
            errcode = self.PyTracer.GetDecodeStatus()
            if errcode != pyptracer.pt_error_code.pte_ok:
                if not block.ip in error_count:
                    if errcode == pyptracer.pt_error_code.pte_nomap and self.LoadImage:
                        error_count[block.ip] = 1
                        if self.LoadImageFile(block.ip):
                            move_forward = False
                            continue
                        else:
                            print('* block.ip=%x ~ %x errorcode= %s' % (block.ip, block.end_ip, errcode))
                            self.GetDisasmLine(block.ip)
                else:
                    error_count[block.ip] += 1

            block_count += 1
            move_forward = True
        self.RecordBlockOffsets()

    def WriteBlockIPMap(self, filename):
        pickle.dump(self.BlockIPMap, open(filename, "wb" ) )

