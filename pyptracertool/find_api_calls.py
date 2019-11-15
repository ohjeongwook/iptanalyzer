if __name__ == '__main__':
    import argparse

    import block
    import dump
    import decoder

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-c', action = "store", dest = "cache")
    parser.add_argument('-p', action = "store", default = "", dest = "pt")
    parser.add_argument('-d', action = "store", default = "", dest = "dump")
    parser.add_argument('-s', action = "store", dest = "symbol")
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int)

    args = parser.parse_args()

    block_analyzer = block.CacheReader(args.cache, args.pt)

    dump_loader = dump.Loader(args.dump)
    if args.symbol:
        address = dump_loader.ResolveSymbolAddress(args.symbol)

        for (sync_offset, offset) in block_analyzer.EnumerateBlocks(address, cr3 = args.cr3):
            print('> sync_offset = %x / offset = %x' % (sync_offset, offset))

            pt_log_analyzer = decoder.PTLogAnalyzer(args.dump, dump_symbols = True, load_image = True)
            pt_log_analyzer.OpenPTLog(args.pt, start_offset = sync_offset, end_offset = offset+2)
            for insn in pt_log_analyzer.EnumerateInstructions(move_forward = False, instruction_offset = offset):
                disasmline = pt_log_analyzer.GetDisasmLine(insn)
                print('\tInstruction: %s' % (disasmline))
