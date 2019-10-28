import os
import sys
sys.path.append(r'..\x64\Debug')

from zipfile import ZipFile

import pyptracer

if not os.path.isfile('../TestFiles/trace.pt'):
    print("* Extracting test trace file:")
    with ZipFile('../TestFiles/trace.zip', 'r') as zf:
       zf.extractall()

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

    print('%x: %x (%.2x) - %d' % (p.GetOffset(), insn.ip, insn.raw, p.GetNextInsnStatus()))
    
    if i > 10:
        break

    i += 1