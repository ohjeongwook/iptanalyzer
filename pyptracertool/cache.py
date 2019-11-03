import os
import pickle

class Merger:
    def __init__(self):
        self.BlockOffsets = {}

    def ReadDirectory(self, dirname):
        for basename in os.listdir(dirname):
            if not basename.endswith('.p'):
                continue
            self.Read(os.path.join(dirname, basename))

    def Read(self, filename):
        for (address, offset_map) in pickle.load(open(filename, "rb")).items():
            if not address in self.BlockOffsets:
                self.BlockOffsets[address] = {}

            for (sync_offset, v) in offset_map.items():
                if not sync_offset in self.BlockOffsets[address]:
                    self.BlockOffsets[address][sync_offset] = {}

                for (offset, v2) in v.items():
                    self.BlockOffsets[address][sync_offset][offset] = v

    def Write(self, filename):
        pickle.dump(self.BlockOffsets, open(filename, "wb" ) )

if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-c', action = "store", dest = "cache")
    parser.add_argument('-o', action = "store", dest = "output")

    args = parser.parse_args()

    merger = Merger()
    merger.ReadDirectory(args.cache)
    merger.Write(args.output)