import os
import sys
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import capstone

import pyptracertool
import windbgtool.debugger

def DecodeBlock(pt_filename, dump_filename, block_range):
    (start_offset, end_offset) = block_range
    pytracer = pyptracertool.Decoder(pt_filename, dump_filename, dump_symbols = True, load_image = True, start_offset = start_offset, end_offset = end_offset)
    pytracer.DecodeBlock('%d.p' % start_offset)

if __name__ == '__main__':
    import argparse
    import multiprocessing

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('--offset', type=int)

    args = parser.parse_args()

    pt_filename = '../TestFiles/trace.pt'
    dump_filename = '../TestFiles/notepad.exe.dmp'

    pytracer = pyptracertool.Decoder(pt_filename, dump_filename, dump_symbols = False)
    pytracer.DecodeBlock()

    cpu_count = multiprocessing.cpu_count()
    offsets_count = len(pytracer.BlockOffsets)
    chunk_size = int(offsets_count / cpu_count)

    block_ranges = []
    for start_index in range(0, offsets_count, chunk_size):
        end_index = start_index + chunk_size
        if end_index < offsets_count:
            block_ranges.append((pytracer.BlockOffsets[start_index], pytracer.BlockOffsets[end_index]))
        else:
            block_ranges.append((pytracer.BlockOffsets[start_index], 0))

    procs = []
    for block_range in block_ranges:
        proc = multiprocessing.Process(target=DecodeBlock, args=(pt_filename, dump_filename, block_range,))
        procs.append(proc)
        proc.start()

    for proc in procs:
        proc.join()
