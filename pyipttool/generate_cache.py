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
import multiprocessing

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

def decode_block(pt_filename, dump_filename, temp_directory, cache_filename, start_offset = 0, end_offset = 0, debug_level = 0):
    logging.debug("decode_block: dump_filename: %s, cache_filename: %s" % (dump_filename, cache_filename))

    pt_log_analyzer = pyipttool.ipt.Analyzer(dump_filename, dump_symbols = False, load_image = True, temp_directory = temp_directory, debug_level = debug_level)
    pt_log_analyzer.open_ipt_log(pt_filename, start_offset = start_offset, end_offset = end_offset)

    try:
        logging.debug("# pt_log_analyzer.record_block_offsets")
        pt_log_analyzer.record_block_offsets()
    except:
        tb = traceback.format_exc()
        logging.debug("# decode_block exception: %s" % str(tb))

    logging.debug("# decode_block: Writing %.16x ~ %.16x to %s" % (start_offset, end_offset, cache_filename))
    if cache_filename:
        try:
            cache_writer = pyipttool.cache.Writer(pt_log_analyzer.records)
            cache_writer.save(cache_filename)
        except:
            tb = traceback.format_exc()
            logging.debug("# decode_block save exception: %s" % tb)

    pt_log_analyzer.close()

def decode_blocks_function(data):
    (arguments, start_offset, end_offset, cache_filename) = data
    (pt_filename, dump_filename, temp_directory, log_directory, debug_level) = arguments
    set_log_file(os.path.join(log_directory, 'decode_blocks_function-%.16x-%.16x.log' % (start_offset, end_offset)))
    logging.debug("# decode_blocks_function: %.16x ~ %.16x" % (start_offset, end_offset))
    logging.debug("* debug_level: %d" % (debug_level))
    decode_block(pt_filename, dump_filename, temp_directory, cache_filename, start_offset, end_offset, debug_level = debug_level)

def start_process():
    print('Starting', multiprocessing.current_process().name)
    logging.basicConfig(level=logging.DEBUG, filename = '', filemode = 'w', format = '%(name)s - %(levelname)s - %(message)s')

if __name__ == '__main__':
    import argparse
    import tempfile

    import pyipttool.cache

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-p', action = "store", default = "", dest = "pt_filename")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_filename")
    parser.add_argument('-o', action = "store", default="blocks.cache", dest = "cache_filename")
    parser.add_argument('-t', action = "store", default = tempfile.gettempdir(), dest = "temp_directory")
    parser.add_argument('-l', action = "store", default = os.path.join(os.getcwd(), "logs"), dest = "log_directory")
    parser.add_argument('-O', dest = "offset", default = 0, type = auto_int)
    parser.add_argument('-D', dest = "debug_level", default = 0, type = auto_int)

    args = parser.parse_args()

    if not os.path.isdir(args.log_directory):
        try:
            os.makedirs(args.log_directory)
        except:
            traceback.print_exc()

    use_multiprocess = True

    if args.debug_level > 0:
        log_filename = os.path.join(args.log_directory, 'generate_cache.log')
        logging.basicConfig(level=logging.DEBUG, filename = log_filename, filemode = 'w', format = '%(name)s - %(levelname)s - %(message)s')

    if not use_multiprocess:
        decode_block(args.pt_filename, args.dump_filename, args.temp_directory, args.cache_filename, debug_level = debug_level)
    else:
        process_count = multiprocessing.cpu_count()

        ipt_analyzer = pyipttool.ipt.Analyzer(args.dump_filename, dump_symbols = False, load_image = False)
        ipt_analyzer.open_ipt_log(args.pt_filename, start_offset = 0)
        sync_offsets = ipt_analyzer.enumerate_sync_offsets()
        arguments = (args.pt_filename, args.dump_filename, args.temp_directory, args.log_directory, args.debug_level)
        inputs = []
        offsets_count = len(sync_offsets)
        chunk_size = int(offsets_count / process_count)
        cache_filenames = []
        for start_index in range(0, offsets_count, chunk_size):
            end_index = start_index + chunk_size
            if end_index < offsets_count:
                start_offset = sync_offsets[start_index]
                end_offset = sync_offsets[end_index]
            else:
                start_offset = sync_offsets[start_index]
                end_offset = 0

            cache_filename = os.path.join(args.temp_directory, 'block-%.16x-%.16x.cache' % (start_offset, end_offset))
            cache_filenames.append(cache_filename)

            logging.debug("# queing: %.16x ~ %.16x" % (start_offset, end_offset))

            inputs.append((arguments, start_offset, end_offset, cache_filename))

        print("Launching decode block functions...")       

        pool = multiprocessing.Pool(processes = process_count,
                                    initializer = start_process)
        pool_outputs = pool.map(decode_blocks_function, inputs)
        pool.close()
        pool.join()

        print("Merging block cache files...")
        merger = pyipttool.cache.Merger(args.cache_filename)
        merger.add_record_files(cache_filenames)
        merger.save()

        for filename in cache_filenames:
            os.unlink(filename)
