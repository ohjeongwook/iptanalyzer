import block
    
if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-c', action = "store", dest = "cache")
    parser.add_argument('-p', action = "store", default = "", dest = "pt")
    parser.add_argument('-d', action = "store", default = "", dest = "dump")
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int)

    parser.add_argument('-s', dest = "start_address", default = 0, type = auto_int)
    parser.add_argument('-e', dest = "end_address", default = 0, type = auto_int)

    parser.add_argument('-S', dest = "start_offset", default = 0, type = auto_int)
    parser.add_argument('-E', dest = "end_offset", default = 0, type = auto_int)

    args = parser.parse_args()

    block_analyzer = block.CacheReader(args.cache, args.pt, args.dump)

    block_analyzer.DumpBlocks(cr3 = args.cr3, start_address = args.start_address, end_address = args.end_address, dump_instructions = True)
