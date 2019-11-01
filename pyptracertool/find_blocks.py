import block
    
if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-c', action = "store", dest = "cache")
    parser.add_argument('-p', action = "store", dest = "pt")
    parser.add_argument('-d', action = "store", dest = "dump")
    parser.add_argument('-s', action = "store", dest = "symbol")

    args = parser.parse_args()

    block_analyzer = block.Analyzer(args.cache, args.pt, args.dump)

    module_name = args.symbol.split('!')[0]
    block_analyzer.LoadModuleSymbols(module_name)
    block_analyzer.DumpSymbolLocations(args.symbol, dump_instructions = True)
