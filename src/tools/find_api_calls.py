import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

if __name__ == '__main__':
    import argparse
    import json
    import iptanalyzer.cache
    import iptanalyzer.ipt
    import windbgtool.debugger
    import tools.arguments

    parser = argparse.ArgumentParser(description='This is a tool to find calls to APIs or functions')
    tools.arguments.add_arguments(parser)
    parser.add_argument('-o', action = "store", dest = "output_filename", default = 'apis_blocks.json', metavar = "<output filename>", help = "Output filename")
    parser.add_argument('-s', action = "store", dest = "symbol", metavar = "<api name>", help = "API Symbol in ! notation e.g. kernel32!CreateFileW", required=True)
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

            ipt_loader = iptanalyzer.ipt.Loader(args.dump_filename, dump_symbols = True, load_image = True)
            ipt_loader.open(args.pt_filename, start_offset = sync_offset, end_offset = offset+2)

            instructions = []
            for instruction in ipt_loader.decode_instructions(offset = offset):
                instruction_str = debugger.get_disassembly_line(instruction.ip)
                print('\tInstruction: %s' % (instruction_str))
                instructions.append({'IP': instruction.ip, 'Instruction': instruction_str})

            apis_blocks.append({
                'SyncOffset': sync_offset,
                'Offset': offset,
                'Instructions': instructions})

        with open(args.output_filename, 'w') as fd:
            json.dump(apis_blocks, fd, indent = 4)
