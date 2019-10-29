import os
import sys
sys.path.append(r'..\x64\Debug')

import pprint
from zipfile import ZipFile
import capstone

import pyptracer
import windbgtool.debugger

class PyTracer:
    def __init__(self, pt_zip_filename, pt_filename, dump_filename = ''):
        if dump_filename:
            self.Debugger = windbgtool.debugger.DbgEngine()
            #self.Debugger.SetLogLevel(True)
            self.Debugger.LoadDump(dump_filename)

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

    def Run(self):
        self.PyTracer.StartInstructionDecoding()

        move_forward = True
        i = 0
        while 1:
            insn = self.PyTracer.DecodeInstruction(move_forward)
            if not insn:
                break

            raw_bytes = insn.GetRawBytes()
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            for disas in md.disasm(bytearray(raw_bytes), insn.ip):        
                print('%x: %s %s' % (disas.address, disas.mnemonic, disas.op_str))
                break

            errcode = self.PyTracer.GetNextInsnStatus()
            if errcode == pyptracer.pt_error_code.pte_nomap:
                address_info = self.Debugger.GetAddressInfo(insn.ip)
                base_address = int(address_info['Base Address'], 16)
                region_size = int(address_info['Region Size'], 16)
                dmp_filename = '%x.dmp' % base_address
                self.Debugger.RunCmd('.writemem %s %x L?%x' % (dmp_filename, base_address, region_size))
                self.PyTracer.AddImage(base_address, dmp_filename)
                move_forward = False
                continue

            i += 1
            move_forward = True

if __name__ == '__main__':
    pytracer = PyTracer('../TestFiles/trace.zip', '../TestFiles/trace.pt', '../TestFiles/notepad.exe.dmp')
    pytracer.Run()
