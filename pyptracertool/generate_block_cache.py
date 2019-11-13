import os
import sys
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta
import logging
import uuid
import traceback

import capstone

import decoder
import windbgtool.debugger

def SetLogFile(filename):
    fh = logging.FileHandler(filename, 'w')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)

    log = logging.getLogger()
    for hdlr in log.handlers[:]:
        log.removeHandler(hdlr)
    log.addHandler(fh)

def DecodeBlockProcess(pt_filename, dump_filename, queue, temp_foldername):
    log_filename = str(uuid.uuid1()) + '.log'
    logging.basicConfig(level=logging.DEBUG, filename = log_filename, filemode = 'w', format = '%(name)s - %(levelname)s - %(message)s')

    while True:
        msg = queue.get()
        if msg == None:
            break

        (start_offset, end_offset, block_offsets_filename) = msg

        SetLogFile('DecodeBlockProcess-%.16x-%.16x.log' % (start_offset, end_offset))
        logging.debug("# DecodeBlockProcess: %.16x ~ %.16x" % (start_offset, end_offset))

        pytracer = decoder.PTLogAnalyzer(dump_filename, dump_symbols = False, load_image = True, temp_foldername = temp_foldername)
        pytracer.OpenPTLog(pt_filename, start_offset = start_offset, end_offset = end_offset)

        try:
            pytracer.DecodeBlocks()
        except:
            tb = traceback.format_exc()
            logging.debug("# DecodeBlockProcess DecodeBlocks Exception: %s" % tb)

        logging.debug("# DecodeBlockProcess: Writing %.16x ~ %.16x to %s" % (start_offset, end_offset, block_offsets_filename))
        if block_offsets_filename:
            try:
                pytracer.WriteBlockOffsets(block_offsets_filename)
            except:
                tb = traceback.format_exc()
                logging.debug("# DecodeBlockProcess WriteBlockOffsets Exception: %s" % tb)

if __name__ == '__main__':
    import argparse
    import tempfile

    import cache

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-p', action = "store", default = "", dest = "pt")
    parser.add_argument('-d', action = "store", default = "", dest = "dump")
    parser.add_argument('-c', action = "store", default="blocks.cache", dest = "block_cache")
    parser.add_argument('-t', action = "store", default=tempfile.gettempdir(), dest = "temp")
    parser.add_argument('-o', dest = "offset", default = 0, type = auto_int)

    args = parser.parse_args()

    pytracer = decoder.PTLogAnalyzer(args.dump, dump_symbols = False, progress_report_interval = 100)
    pytracer.OpenPTLog(args.pt, start_offset = 0)
    pytracer.DecodeBlocks()

    import multiprocessing

    cpu_count = multiprocessing.cpu_count()
    pqueue = multiprocessing.Queue()

    print("Launching block analyzers...")
    procs = []
    block_offsets_filenames = []

    for i in range(0, cpu_count, 1):
        proc = multiprocessing.Process(target = DecodeBlockProcess, args=(args.pt, args.dump, pqueue, args.temp))
        procs.append(proc)
        proc.start()

    chunk_size = 1
    block_ranges = []

    offsets_count = len(pytracer.BlockSyncOffsets)
    for start_index in range(0, offsets_count, chunk_size):
        end_index = start_index + chunk_size
        if end_index < offsets_count:
            start_offset = pytracer.BlockSyncOffsets[start_index]
            end_offset = pytracer.BlockSyncOffsets[end_index]
        else:
            start_offset = pytracer.BlockSyncOffsets[start_index]
            end_offset = 0

        block_offsets_filename = os.path.join(args.temp, 'block-%.16x-%.16x.cache' % (start_offset, end_offset))
        block_offsets_filenames.append(block_offsets_filename)
        pqueue.put((start_offset, end_offset, block_offsets_filename))

    for i in range(0, cpu_count, 1):
        pqueue.put(None)

    for proc in procs:
        proc.join()

    print("Merging block cache files...")
    merger = cache.Merger()
    for filename in block_offsets_filenames:
        merger.Read(filename)
        #os.unlink(filename)
    merger.Write(args.block_cache)