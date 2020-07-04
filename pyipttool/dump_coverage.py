import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

if __name__ == '__main__':
    import argparse
    import logging

    import windbgtool.debugger

    import pyipttool.cache    
    import pyipttool.coverage

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-p', action = "store", default = "", dest = "pt_filename")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_filename")

    parser.add_argument('-m', action = "store", dest = "module_name", default = "")
    parser.add_argument('-o', action = "store", dest = "output_filename", default = "coverage.txt")
    
    parser.add_argument('-D', dest = "debug_level", default = 0, type = auto_int)
    parser.add_argument('-O', action = "store", dest = "debug_filename", default = "stdout")
    
    parser.add_argument('-s', dest = "start_address", default = 0, type = auto_int)
    parser.add_argument('-e', dest = "end_address", default = 0, type = auto_int)
    
    parser.add_argument('-c', action = "store", dest = "cache_file")
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int)    

    args = parser.parse_args()

    if args.debug_level > 0:
        handlers = []
        if args.debug_filename == 'stdout':
            handlers.append(logging.StreamHandler())
        else:
            handlers.append(logging.FileHandler(args.debug_filename))

        logging.basicConfig(
            level=logging.DEBUG,
            format = '%(name)s - %(levelname)s - %(message)s',
            handlers = handlers
        )

    debugger = windbgtool.debugger.DbgEngine()
    debugger.load_dump(args.dump_filename)
    debugger.enumerate_modules()

    start_address = 0
    end_address = 0

    if args.module_name:
        module_name = args.module_name
        (start_address, end_address) = debugger.get_module_range(args.module_name)
    else:
        module_name = ''
        start_address = args.start_address
        end_address = args.end_address

    if args.cache_file:
        block_analyzer = pyipttool.cache.Reader(args.cache_file)
        coverage_logger = pyipttool.coverage.Logger(module_name, start_address, end_address, args.pt_filename, args.dump_filename, debugger = debugger)
        
        for (offset, address, end_address, sync_offset) in block_analyzer.enumerate_block_range(cr3 = args.cr3, start_address = start_address, end_address = end_address):
            coverage_logger.add_block(offset, address, end_address, sync_offset)

        if args.output_filename:
            coverage_logger.save(args.output_filename)
        else:
            coverage_logger.print()
