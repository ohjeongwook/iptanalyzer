import os
import sys
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta
import tempfile

import capstone

import pyptracer
import windbgtool.debugger

class PTLogAnalyzer:
    def __init__(self, dump_filename = '', load_image = False, dump_instructions = False, dump_symbols = True, disassembler = "capstone", progress_report_interval = 0, temp_foldername = ''):
        self.ProgressReportInterval = progress_report_interval
        self.DumpInstructions = dump_instructions
        self.DumpSymbols = dump_symbols
        self.LoadImage = load_image
        self.Disassembler = disassembler
        self.LoadedMemories = {}
        self.AddressToSymbols = {}
        self.ErrorLocations = {}
        self.AddressList = None
        self.BlockIPsToOffsets = {}
        self.BlockOffsetsToIPs = {}
        self.BlockSyncOffsets = []

        if temp_foldername:
            self.TempFolderName = temp_foldername
        else:
            self.TempFolderName = tempfile.gettempdir()

        if dump_filename:
            self.Debugger = windbgtool.debugger.DbgEngine()
            self.Debugger.LoadDump(dump_filename)
            self.AddressList = self.Debugger.GetAddressList()

            if self.DumpSymbols:
                self.Debugger.EnumerateModules()

    def OpenPTLog(self, pt_filename, start_offset = 0, end_offset = 0):
        self.StartOffset = start_offset
        self.EndOffset = end_offset
        self.LoadedMemories = {}

        self.PyTracer = pyptracer.PTracer()
        self.PyTracer.Open(pt_filename, self.StartOffset , self.EndOffset)

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
            module_name = address_info['Module Name'].split('.')[0]
            for (address, symbol) in self.Debugger.EnumerateModuleSymbols([module_name, ]).items():
                self.AddressToSymbols[address] = symbol

        base_address = region_size = None
        if use_address_map and self.AddressList:
            for mem_info in self.AddressList:
                if mem_info['BaseAddr'] <= ip and ip <= mem_info['EndAddr']:
                    base_address = mem_info['BaseAddr']
                    region_size = mem_info['RgnSize']
                    break
        
        if (base_address == None or region_size == None) and address_info:
            base_address = int(address_info['Base Address'], 16)
            region_size = int(address_info['Region Size'], 16)

        if base_address == None or region_size == None:
            print('LoadImageFile failed to find base address for %x' % ip)
            return False

        if base_address in self.LoadedMemories:
            return self.LoadedMemories[base_address]

        self.LoadedMemories[base_address] = False
        dump_filename = os.path.join(self.TempFolderName, '%x.dmp' % base_address)
        writemem_cmd = '.writemem %s %x L?%x' % (dump_filename, base_address, region_size)
        self.Debugger.RunCmd(writemem_cmd)
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
            try:
                return self.Debugger.RunCmd('u %x L1' % (insn.ip))
            except:
                pass

        return ''

    # True:  Handled error
    # False: No errors or repeated and ignored error
    def ProcessError(self, ip):
        errcode = self.PyTracer.GetDecodeStatus()
        if errcode != pyptracer.pt_error_code.pte_ok:
            if errcode == pyptracer.pt_error_code.pte_nomap:
                if ip in self.ErrorLocations:
                    return False

                self.ErrorLocations[ip] = 1

                if self.LoadImage and self.LoadImageFile(ip):
                    return True

        return False 

    def EnumerateInstructions(self, move_forward = True, instruction_offset = 0, start_address = 0, end_address = 0):
        instruction_count = 0
        while 1:
            insn = self.PyTracer.DecodeInstruction(move_forward)
            if not insn:
                break

            if self.ProcessError(insn.ip):
                move_forward = False
            else:
                offset = self.PyTracer.GetOffset()
                if self.ProgressReportInterval > 0 and instruction_count % self.ProgressReportInterval == 0:
                    size = self.PyTracer.GetSize()
                    progress_offset = offset - self.StartOffset
                    print('EnumerateInstructions: offset: %x progress: %x/%x (%f%%)' % (
                        offset,
                        progress_offset,
                        size, 
                        (progress_offset*100)/size))

                if instruction_offset > 0:
                    if instruction_offset == offset:
                        yield insn

                        if self.DumpInstructions:
                            disasmline = self.GetDisasmLine(insn)
                            print('%x: %s' % (offset, disasmline))

                    if instruction_offset < offset:
                        break
                else:
                    if (start_address == 0 and end_address == 0) or start_address <= insn.ip and insn.ip <= end_address:
                        yield insn

                        if self.DumpInstructions:
                            disasmline = self.GetDisasmLine(insn)
                            print('%x: %s' % (offset, disasmline))

                instruction_count += 1
                move_forward = True

    def RecordBlockOffsets(self, block, cr3 = 0):
        sync_offset = self.PyTracer.GetSyncOffset()
        offset = self.PyTracer.GetOffset()

        if not cr3 in self.BlockIPsToOffsets:
            self.BlockIPsToOffsets[cr3] = {}

        self.BlockSyncOffsets.append(sync_offset)
        if not block.ip in self.BlockIPsToOffsets[cr3]:
            self.BlockIPsToOffsets[cr3][block.ip] = {}

        if not sync_offset in self.BlockIPsToOffsets[cr3][block.ip]:
            self.BlockIPsToOffsets[cr3][block.ip][sync_offset]={}

        if not offset in self.BlockIPsToOffsets[cr3][block.ip][sync_offset]:
            self.BlockIPsToOffsets[cr3][block.ip][sync_offset][offset] = 1
        else:
            self.BlockIPsToOffsets[cr3][block.ip][sync_offset][offset] += 1

        if not cr3 in self.BlockOffsetsToIPs:
            self.BlockOffsetsToIPs[cr3] = {}

        if not offset in self.BlockOffsetsToIPs[cr3]:
            self.BlockOffsetsToIPs[cr3][offset] = []

        self.BlockOffsetsToIPs[cr3][offset].append({'IP': block.ip, 'SyncOffset': sync_offset})

    def DecodeBlocks(self, move_forward = True):
        self.BlockIPsToOffsets = {}
        self.BlockOffsetsToIPs = {}
        self.BlockSyncOffsets = []

        while 1:
            block = self.PyTracer.DecodeBlock(move_forward)
            if not block:
                break

            if self.ProcessError(block.ip):
                move_forward = False
            else:
                self.RecordBlockOffsets(block, self.PyTracer.GetCurrentCR3())
                move_forward = True

    def EnumerateBlocks(self, log_filename = '', move_forward = True, block_offset = 0):
        self.BlockIPsToOffsets = {}
        self.BlockOffsetsToIPs = {}
        self.BlockSyncOffsets = []
        self.StartTime = datetime.now()
        while 1:
            block = self.PyTracer.DecodeBlock(move_forward)
            if not block:
                break

            if self.ProcessError(block.ip):
                move_forward = False
            else:
                sync_offset = self.PyTracer.GetSyncOffset()
                offset = self.PyTracer.GetOffset()

                if self.ProgressReportInterval > 0 and block_count % self.ProgressReportInterval == 0:
                    time_diff = datetime.now() - self.StartTime
                    if time_diff.seconds > 0:
                        speed = block_count/time_diff.seconds
                    else:
                        speed = 0
                    size = self.PyTracer.GetSize()
                    relative_offset = sync_offset - self.StartOffset
                    print('DecodeBlock: %x +%x @ %d/%d (%f%%) speed: %d blocks/sec' % (self.StartOffset, block_count, relative_offset, size, (relative_offset*100)/size, speed))

                if self.DumpInstructions:
                    print('%x (%x): %s' % (sync_offset, offset, self.AddressToSymbols[block.ip]))

                self.RecordBlockOffsets(block, self.PyTracer.GetCurrentCR3())

                if block_offset > 0:
                    if block_offset == offset:
                        yield block

                    if block_offset < offset:
                        break
                else:
                    yield block

                move_forward = True

    def WriteBlockOffsets(self, filename):
        pickle.dump([self.BlockIPsToOffsets, self.BlockOffsetsToIPs], open(filename, "wb" ) )
