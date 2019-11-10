import block
    
if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-c', action = "store", dest = "cache")
    parser.add_argument('-p', action = "store", dest = "pt")
    parser.add_argument('-d', action = "store", dest = "dump")
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int)

    args = parser.parse_args()

    block_analyzer = block.Analyzer(args.cache, args.pt, args.dump)

    block_analyzer.DumpBlocks(cr3 = args.cr3, dump_instructions = True)
