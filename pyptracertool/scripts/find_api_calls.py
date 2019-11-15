import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

if __name__ == '__main__':
    import argparse

    import pyptracertool.cache
    import pyptracertool.dump
    import pyptracertool.ipt

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-c', action = "store", dest = "cache_file")
    parser.add_argument('-p', action = "store", default = "", dest = "pt_file")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_file")
    parser.add_argument('-s', action = "store", dest = "symbol")
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int)

    args = parser.parse_args()

    block_analyzer = pyptracertool.cache.Reader(args.cache_file, args.pt_file)

    dump_loader = pyptracertool.dump.Loader(args.dump_file)
    if args.symbol:
        address = dump_loader.ResolveSymbolAddress(args.symbol)

        for (sync_offset, offset) in block_analyzer.EnumerateBlocks(address, cr3 = args.cr3):
            print('> sync_offset = %x / offset = %x' % (sync_offset, offset))

            pt_log_analyzer = pyptracertool.ipt.LogAnalyzer(args.dump_file, dump_symbols = True, load_image = True)
            pt_log_analyzer.OpenPTLog(args.pt_file, start_offset = sync_offset, end_offset = offset+2)
            for insn in pt_log_analyzer.EnumerateInstructions(move_forward = False, instruction_offset = offset):
                disasmline = dump_loader.GetDisasmLine(insn.ip)
                print('\tInstruction: %s' % (disasmline))
