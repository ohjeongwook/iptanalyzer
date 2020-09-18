import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

if __name__ == '__main__':
    import argparse
    import logging

    import windbgtool.debugger

    import iptanalyzer.cache    
    import iptanalyzer.coverage
    import tools.arguments

    parser = argparse.ArgumentParser(description='This is a tool to generate coverage file that can be used by lighthouse')
    tools.arguments.add_arguments(parser)
    tools.arguments.add_address_range_arguments(parser)
    tools.arguments.add_module_arguments(parser)
    parser.add_argument('-o', dest = "output_filename", default = "coverage.txt", metavar = "<output filename>", help = "Output coverage filename")   
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

    if args.cache_filename:
        block_analyzer = iptanalyzer.cache.Reader(args.cache_filename)
        coverage_logger = iptanalyzer.coverage.Logger(module_name, start_address, end_address, args.pt_filename, args.dump_filename, debugger = debugger)
        
        for (offset, address, end_address, sync_offset) in block_analyzer.enumerate_block_range(cr3 = args.cr3, start_address = start_address, end_address = end_address):
            coverage_logger.add_block(offset, address, end_address, sync_offset)

        if args.output_filename:
            coverage_logger.save(args.output_filename)
        else:
            coverage_logger.print()
