import os
import sys

sys.path.append(r'..\x64\Debug')

import pyptracer

p=pyptracer.PTracerLib()
p.Open(r'trace.pt')
p.StartInstructionTrace()

while 1:
    p.DecodeInstruction()
