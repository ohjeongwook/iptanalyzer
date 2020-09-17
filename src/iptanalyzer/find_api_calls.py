import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

if __name__ == '__main__':
    import argparse
    import json
    import iptanalyzer.cache
    import iptanalyzer.ipt
    import windbgtool.debugger

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-c', action = "store", dest = "cache_filename")
    parser.add_argument('-o', action = "store", dest = "output_filename", default = 'apis_blocks.json')
    parser.add_argument('-p', action = "store", default = "", dest = "pt_filename")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_filename")
    parser.add_argument('-s', action = "store", dest = "symbol")
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int)

    args = parser.parse_args()

    debugger = windbgtool.debugger.DbgEngine()
    debugger.load_dump(args.dump_filename)
    debugger.enumerate_modules()

    if args.symbol:
        address = debugger.resolve_symbol(args.symbol)
        apis_blocks = []

        block_analyzer = iptanalyzer.cache.Reader(args.cache_filename)
        for (sync_offset, offset) in block_analyzer.enumerate_blocks(address, cr3 = args.cr3):
            print('> sync_offset = %x / offset = %x' % (sync_offset, offset))

            pt_log_analyzer = iptanalyzer.ipt.Analyzer(args.dump_filename, dump_symbols = True, load_image = True)
            pt_log_analyzer.open_ipt_log(args.pt_filename, start_offset = sync_offset, end_offset = offset+2)

            instructions = []
            for instruction in pt_log_analyzer.decode_instructions(offset = offset):
                instruction_str = debugger.get_disassembly_line(instruction.ip)
                print('\tInstruction: %s' % (instruction_str))
                instructions.append({'IP': instruction.ip, 'Instruction': instruction_str})

            apis_blocks.append({
                'SyncOffset': sync_offset,
                'Offset': offset,
                'Instructions': instructions})

        with open(args.output_filename, 'w') as fd:
            json.dump(apis_blocks, fd, indent = 4)
