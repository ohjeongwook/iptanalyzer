import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

if __name__ == '__main__':
    import argparse

    import pyipttool.cache
    import pyipttool.ipt
    import windbgtool.debugger

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-c', action = "store", dest = "cache_file")
    parser.add_argument('-p', action = "store", default = "", dest = "pt_file")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_file")
    parser.add_argument('-s', action = "store", dest = "symbol")
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int)

    args = parser.parse_args()

    block_analyzer = pyipttool.cache.Reader(args.cache_file, args.pt_file)

    debugger = windbgtool.debugger.DbgEngine()
    debugger.load_dump(args.dump_file)
    debugger.enumerate_modules()

    if args.symbol:
        address = debugger.resolve_symbol(args.symbol)
        for (sync_offset, offset) in block_analyzer.enumerate_blocks(address, cr3 = args.cr3):
            print('> sync_offset = %x / offset = %x' % (sync_offset, offset))

            pt_log_analyzer = pyipttool.ipt.Analyzer(args.dump_file, dump_symbols = True, load_image = True)
            pt_log_analyzer.open_ipt_log(args.pt_file, start_offset = sync_offset, end_offset = offset+2)
            for instruction in pt_log_analyzer.decode_instructions(offset = offset):
                print('\tInstruction: %s' % (debugger.get_disassembly_line(instruction.ip)))
