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

def DecodeBlock(pt_filename, dump_filename, block_range, block_offsets_filename = '', temp_foldername = '.'):
    (start_offset, end_offset) = block_range
    pytracer = decoder.PTLogAnalyzer(pt_filename, dump_filename, dump_symbols = False, load_image = True, start_offset = start_offset, end_offset = end_offset, temp_foldername = temp_foldername)
    pytracer.DecodeBlock()

    if block_offsets_filename:
        pytracer.WriteBlockOffsets(block_offsets_filename)

if __name__ == '__main__':
    import argparse
    import multiprocessing
    import tempfile

    import cache

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-p', action = "store", dest = "pt")
    parser.add_argument('-d', action = "store", dest = "dump")
    parser.add_argument('-c', action = "store", default="blocks.cache", dest = "block_cache")
    parser.add_argument('-t', action = "store", default=tempfile.gettempdir(), dest = "temp")
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
    block_offsets_filenames = []
    for block_range in block_ranges:
        block_offsets_filename = os.path.join(args.temp, '%d.p' % block_range[0])
        block_offsets_filenames.append(block_offsets_filename)
        proc = multiprocessing.Process(target=DecodeBlock, args=(args.pt, args.dump, block_range, block_offsets_filename, args.temp))
        procs.append(proc)
        proc.start()

    for proc in procs:
        proc.join()

    merger = cache.Merger()
    for filename in block_offsets_filenames:
        merger.Read(filename)
        os.unlink(filename)
    merger.Write(args.block_cache)
