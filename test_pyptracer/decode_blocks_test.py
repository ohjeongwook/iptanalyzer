import os
import sys
sys.path.append(r'..\x64\Debug')

import pprint
import decode_blocks

pt_filename = '../TestFiles/trace.pt'
dmp_filename = '../TestFiles/notepad.exe.dmp'

decode_blocks.DecodeBlock(pt_filename, dmp_filename, (1744833744, 1744835680))
