import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta
import logging
import uuid
import traceback

import pyipttool.ipt
import pyipttool.cache

def set_log_file(filename):
    fh = logging.FileHandler(filename, 'w')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)

    log = logging.getLogger()
    for hdlr in log.handlers[:]:
        log.removeHandler(hdlr)
    log.addHandler(fh)

def decode_block_process(pt_filename, dump_filename, queue, temp_foldername, log_directory):
    log_filename = os.path.join(log_directory, str(uuid.uuid1()) + '.log')
    logging.basicConfig(level=logging.DEBUG, filename = log_filename, filemode = 'w', format = '%(name)s - %(levelname)s - %(message)s')

    while True:
        msg = queue.get()
        if msg == None:
            break

        (start_offset, end_offset, cache_filename) = msg

        decode_block_process_log_filename = os.path.join(log_directory, 'decode_block_process-%.16x-%.16x.log' % (start_offset, end_offset))
        set_log_file(decode_block_process_log_filename)

        logging.debug("# decode_block_process: %.16x ~ %.16x" % (start_offset, end_offset))

        pt_log_analyzer = pyipttool.ipt.Analyzer(dump_filename, dump_symbols = False, load_image = True, temp_foldername = temp_foldername)
        pt_log_analyzer.open_ipt_log(pt_filename, start_offset = start_offset, end_offset = end_offset)

        try:
            pt_log_analyzer.decode_blocks()
        except:
            tb = traceback.format_exc()
            logging.debug("# decode_block_process DecodeBlocks Exception: %s" % tb)

        logging.debug("# decode_block_process: Writing %.16x ~ %.16x to %s" % (start_offset, end_offset, cache_filename))
        if cache_filename:
            try:
                cache_writer = pyipttool.cache.Writer(pt_log_analyzer.basic_block_addresss_to_offsets, pt_log_analyzer.block_offsets_to_ips)
                cache_writer.save(cache_filename)
            except:
                tb = traceback.format_exc()
                logging.debug("# decode_block_process WriteBlockOffsets Exception: %s" % tb)

if __name__ == '__main__':
    import argparse
    import tempfile

    import pyipttool.cache

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-p', action = "store", default = "", dest = "pt_filename")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_file")
    parser.add_argument('-o', action = "store", default="blocks.cache", dest = "cache_file")
    parser.add_argument('-t', action = "store", default = tempfile.gettempdir(), dest = "temp")
    parser.add_argument('-l', action = "store", default = os.path.join(os.getcwd(), "logs"), dest = "log_directory")
    parser.add_argument('-O', dest = "offset", default = 0, type = auto_int)

    args = parser.parse_args()

    if not os.path.isdir(args.log_directory):
        try:
            os.makedirs(args.log_directory)
        except:
            traceback.print_exc()

    ipt_analyzer = pyipttool.ipt.Analyzer(args.dump_file, dump_symbols = False, load_image = False, progress_report_interval = 100)
    ipt_analyzer.open_ipt_log(args.pt_filename, start_offset = 0)
    sync_offsets = ipt_analyzer.enumerate_sync_offsets()

    import multiprocessing

    cpu_count = multiprocessing.cpu_count()
    pqueue = multiprocessing.Queue()

    print("Launching block analyzers...")
    procs = []
    cache_filenames = []

    for i in range(0, cpu_count, 1):
        proc = multiprocessing.Process(target = decode_block_process, args=(args.pt_filename, args.dump_file, pqueue, args.temp, args.log_directory))
        procs.append(proc)
        proc.start()

    chunk_size = 1
    block_ranges = []

    offsets_count = len(sync_offsets)
    for start_index in range(0, offsets_count, chunk_size):
        end_index = start_index + chunk_size
        if end_index < offsets_count:
            start_offset = sync_offsets[start_index]
            end_offset = sync_offsets[end_index]
        else:
            start_offset = sync_offsets[start_index]
            end_offset = 0

        cache_filename = os.path.join(args.temp, 'block-%.16x-%.16x.cache' % (start_offset, end_offset))
        cache_filenames.append(cache_filename)
        pqueue.put((start_offset, end_offset, cache_filename))

    for i in range(0, cpu_count, 1):
        pqueue.put(None)

    for proc in procs:
        proc.join()

    print("Merging block cache files...")
    merger = pyipttool.cache.Merger()
    for filename in cache_filenames:
        merger.read(filename)
        os.unlink(filename)
    merger.write(args.cache_file)