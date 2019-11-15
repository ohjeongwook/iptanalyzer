import block
    
if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-c', action = "store", dest = "cache")
    parser.add_argument('-p', action = "store", default = "", dest = "pt")
    parser.add_argument('-d', action = "store", default = "", dest = "dump")
    parser.add_argument('-s', action = "store", dest = "symbol")
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int)

    args = parser.parse_args()

    block_analyzer = block.CacheReader(args.cache, args.pt, args.dump)

    module_name = args.symbol.split('!')[0]
    block_analyzer.LoadModuleSymbols(module_name)
    block_analyzer.DumpSymbolLocations(args.symbol, cr3 = args.cr3, dump_instructions = True)
