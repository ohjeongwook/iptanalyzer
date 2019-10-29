import os
import sys
sys.path.append(r'..\x64\Debug')

from zipfile import ZipFile
import capstone

import pyptracer

def ExtractTracePT():
    if not os.path.isfile('../TestFiles/trace.pt'):
        print("* Extracting test trace file:")
        with ZipFile('../TestFiles/trace.zip', 'r') as zf:
           zf.extractall()

def GetHexLine(raw_bytes):
    raw_line = ''
    for byte in raw_bytes:
        raw_line += '%.2x ' % (byte % 256)

ExtractTracePT()

p=pyptracer.PTracer()
p.Open(r'../TestFiles/trace.pt')

p.AddImage(0x00007ffbb5ba1000, '../TestFiles/00007ffb`b5ba1000.dmp')
p.AddImage(0x00007ffbb7cc1000, '../TestFiles/00007ffb`b7cc1000.dmp')

p.StartInstructionDecoding()

i = 0
while 1:
    insn = p.DecodeInstruction()
    if not insn:
        break

    errcode = p.GetNextInsnStatus()

    raw_bytes = insn.GetRawBytes()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for disas in md.disasm(bytearray(raw_bytes), insn.ip):        
        print('%x: %s %s (%s)' % (disas.address, disas.mnemonic, disas.op_str, errcode))
        break


    if errcode == pyptracer.pt_error_code.pte_nomap:
        break

    if i > 5000:
        break

    i += 1