import os
import sys
sys.path.append(r'..\x64\Debug')

import pprint
from zipfile import ZipFile
import capstone

import pyptracer
import windbgtool.debugger

class PyPTracer:
    def __init__(self, pt_zip_filename, pt_filename, dump_filename = '', dump_instructions = False, dump_symbols = True, disassembler = "capstone"):
        self.DumpInstructions = dump_instructions
        self.DumpSymbols = dump_symbols
        self.Disassembler = disassembler
        self.LoadedMemories = {}
        self.AddressToSymbols = {}

        if dump_filename:
            self.Debugger = windbgtool.debugger.DbgEngine()
            self.Debugger.LoadDump(dump_filename)
            self.AddressList = self.Debugger.GetAddressList()

            if dump_symbols:
                self.Debugger.EnumerateModules()

        self._ExtractTracePT(pt_zip_filename, pt_filename)

        self.PyTracer = pyptracer.PTracer()
        self.PyTracer.Open(pt_filename)

    def _ExtractTracePT(self, pt_zip_filename, pt_filename ):
        if not os.path.isfile(pt_filename):
            print("* Extracting test trace file:")
            with ZipFile(pt_zip_filename, 'r') as zf:
               zf.extractall()

    def _GetHexLine(self, raw_bytes):
        raw_line = ''
        for byte in raw_bytes:
            raw_line += '%.2x ' % (byte % 256)

    def LoadMemory(self, ip, use_address_map = True):
        if ip in self.LoadedMemories:
            return False

        address_info = self.Debugger.GetAddressInfo(ip)
        if self.DumpSymbols:
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
            return False

        dmp_filename = '%x.dmp' % base_address
        self.Debugger.RunCmd('.writemem %s %x L?%x' % (dmp_filename, base_address, region_size))
        self.PyTracer.AddImage(base_address, dmp_filename)
        self.LoadedMemories[base_address] = True

        return True

    def PrintDisassembly(self, ip, raw_bytes = ''):
        symbol = ''
        if ip in self.AddressToSymbols:
            symbol = self.AddressToSymbols[ip]

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        if raw_bytes:
            for disas in md.disasm(bytearray(raw_bytes), ip):
                print('%s (%x): %s %s' % (symbol, disas.address, disas.mnemonic, disas.op_str))
                break
        else:
            disasmline = self.Debugger.RunCmd('u %x L1' % (ip))
            print(disasmline)

    def Run(self):
        self.PyTracer.StartInstructionDecoding()

        move_forward = True

        i = 0
        while 1:
            insn = self.PyTracer.DecodeInstruction(move_forward)
            if not insn:
                break

            if self.DumpInstructions or (self.DumpSymbols and insn.ip in self.AddressToSymbols):
                if self.Disassembler == "capstone":
                    self.PrintDisassembly(insn.ip, insn.GetRawBytes())

                elif self.Disassembler == "windbg":
                    disasmline = self.Debugger.RunCmd('u %x L1' % (insn.ip))
                    print('\t'+disasmline)

            errcode = self.PyTracer.GetNextInsnStatus()
            if errcode != pyptracer.pt_error_code.pte_ok:
                if errcode == pyptracer.pt_error_code.pte_nomap:
                    if self.LoadMemory(insn.ip):
                        move_forward = False
                        continue
                    else:
                        self.PrintDisassembly(insn.ip)
                        print('\terrorcode= %s' % (errcode))

            i += 1
            move_forward = True

if __name__ == '__main__':
    pytracer = PyPTracer(
        '../TestFiles/trace.zip', 
        '../TestFiles/trace.pt',
        '../TestFiles/notepad.exe.dmp', 
        disassembler = "capstone")
    pytracer.Run()
