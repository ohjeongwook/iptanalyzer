import os
import sys
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import capstone

import decoder
import windbgtool.debugger

def DecodeBlock(pt_filename, dump_filename, block_range):
    (start_offset, end_offset) = block_range
    pytracer = decoder.PTLogAnalyzer(pt_filename, dump_filename, dump_symbols = False, load_image = True, start_offset = start_offset, end_offset = end_offset)
    pytracer.DecodeBlock()
    pytracer.WriteBlockOffsets('%d.p' % start_offset)

if __name__ == '__main__':
    import argparse
    import multiprocessing

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-p', action = "store", dest = "pt")
    parser.add_argument('-d', action = "store", dest = "dump")
    parser.add_argument('-o', dest = "offset", default = 0, type = auto_int)

    args = parser.parse_args()

    pytracer = decoder.PTLogAnalyzer(args.pt, args.dump, dump_symbols = False, start_offset = args.offset, progress_report_interval = 100)
    pytracer.DecodeBlock()

    cpu_count = multiprocessing.cpu_count()
    offsets_count = len(pytracer.BlockSyncOffsets)
    chunk_size = int(offsets_count / cpu_count)

    block_ranges = []
    for start_index in range(0, offsets_count, chunk_size):
        end_index = start_index + chunk_size
        if end_index < offsets_count:
            block_ranges.append((pytracer.BlockSyncOffsets[start_index], pytracer.BlockSyncOffsets[end_index]))
        else:
            block_ranges.append((pytracer.BlockSyncOffsets[start_index], 0))

    procs = []
    for block_range in block_ranges:
        proc = multiprocessing.Process(target=DecodeBlock, args=(args.pt, args.dump, block_range,))
        procs.append(proc)
        proc.start()

    for proc in procs:
        proc.join()
