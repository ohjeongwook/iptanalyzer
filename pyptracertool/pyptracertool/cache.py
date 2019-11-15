import os
import pickle

class Merger:
    def __init__(self):
        self.BlockIPsToOffsets = {}
        self.BlockOffsetsToIPs = {}

    def ReadDirectory(self, dirname):
        for basename in os.listdir(dirname):
            if not basename.endswith('.cache'):
                continue
            self.Read(os.path.join(dirname, basename))

    def Read(self, filename):
        try:
            [block_ips_to_offset, block_offsets_to_ips] = pickle.load(open(filename, "rb"))
        except:
            print("Error loading " + filename)
            return

        for (cr3, address_to_offsets) in block_ips_to_offset.items():
            if not cr3 in self.BlockIPsToOffsets:
                self.BlockIPsToOffsets[cr3] = {}

            for (address, offset_map) in address_to_offsets.items():
                if not address in self.BlockIPsToOffsets[cr3]:
                    self.BlockIPsToOffsets[cr3][address] = {}

                for (sync_offset, v) in offset_map.items():
                    if not sync_offset in self.BlockIPsToOffsets[cr3][address]:
                        self.BlockIPsToOffsets[cr3][address][sync_offset] = {}

                    for (offset, v2) in v.items():
                        self.BlockIPsToOffsets[cr3][address][sync_offset][offset] = v

        for (cr3, offsets_to_addresses) in block_offsets_to_ips.items():
            if not cr3 in self.BlockOffsetsToIPs:
                self.BlockOffsetsToIPs[cr3] = {}

            for (offset, addresses) in offsets_to_addresses.items():
                if not offset in self.BlockOffsetsToIPs[cr3]:
                    self.BlockOffsetsToIPs[cr3][offset] = []

                for address in addresses:
                    self.BlockOffsetsToIPs[cr3][offset].append(address)

    def Write(self, filename):
        pickle.dump([self.BlockIPsToOffsets, self.BlockOffsetsToIPs], open(filename, "wb" ) )

if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='PyPTracer')
    parser.add_argument('-c', action = "store", dest = "cache_file")
    parser.add_argument('-o', action = "store", dest = "output")

    args = parser.parse_args()

    merger = Merger()
    merger.ReadDirectory(args.cache_file)
    merger.Write(args.output)