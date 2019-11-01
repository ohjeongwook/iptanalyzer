import sys
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import capstone

import decoder
import windbgtool.debugger

if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-p', action = "store", dest = "pt")
    parser.add_argument('-d', action = "store", dest = "dump")
    parser.add_argument('-s', dest = "start_offset", default = 0, type = auto_int)
    parser.add_argument('-e', dest = "end_offset", default = 0, type = auto_int)
    parser.add_argument('-b', dest = "block_offset", default = 0, type = auto_int)

    args = parser.parse_args()

    pytracer = decoder.PTLogAnalyzer(args.pt, args.dump, 
                                     dump_symbols = False, 
                                     load_image = True, 
                                     start_offset = args.start_offset,
                                     end_offset = args.end_offset,
                                     disassembler = "windbg")

    for block in pytracer.DecodeBlock(move_forward = False, block_offset = args.block_offset):
        print('block.ip: %x ~ %x (%d)' % (block.ip, block.end_ip, block.ninsn))

