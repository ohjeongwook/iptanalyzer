import os
import pprint
import pickle

class Writer:
    def __init__(self, block_ips_to_offsets, block_offsets_to_ips):
        self.BlockIPsToOffsets = block_ips_to_offsets
        self.BlockOffsetsToIPs = block_offsets_to_ips

    def save(self, filename):
        pickle.dump([self.BlockIPsToOffsets, self.BlockOffsetsToIPs], open(filename, "wb" ) )

class Reader:
    def __init__(self, cache_filename, pt_filename):
        self.PTFilename = pt_filename
        [self.BlockIPsToOffsets, self.BlockOffsetsToIPs] = pickle.load(open(cache_filename, "rb"))

    def enumrate_block_range(self, cr3 = 0, start_address = 0, end_address = 0):
        if not cr3 in self.BlockOffsetsToIPs:
            return

        offsets = list(self.BlockOffsetsToIPs[cr3].keys())            
        offsets.sort()

        for offset in offsets:
            for address_info in self.BlockOffsetsToIPs[cr3][offset]:
                address = address_info['IP']
                sync_offset = address_info['SyncOffset']

                if start_address > 0 and end_address > 0:
                    if address < start_address or end_address < address:
                        continue
                yield (sync_offset, offset, address)

    def enumerate_blocks(self, address = None, cr3 = 0):
        if not cr3 in self.BlockIPsToOffsets:
            return

        print('Searching Block Addresss: %x' % (address))
        if not address in self.BlockIPsToOffsets[cr3]:
            return

        for sync_offset in self.BlockIPsToOffsets[cr3][address]:
            for offset in self.BlockIPsToOffsets[cr3][address][sync_offset]:
                yield (sync_offset, offset)

    def find_offsets(self, symbol):
        for block_address in self.BlockAddresses.keys():
            if block_address in self.AddressToSymbols:
                print(self.AddressToSymbols[block_address])

class Merger:
    def __init__(self):
        self.BlockIPsToOffsets = {}
        self.BlockOffsetsToIPs = {}

    def read_directory(self, dirname):
        for basename in os.listdir(dirname):
            if not basename.endswith('.cache'):
                continue
            self.read(os.path.join(dirname, basename))

    def read(self, filename):
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

    def write(self, filename):
        pickle.dump([self.BlockIPsToOffsets, self.BlockOffsetsToIPs], open(filename, "wb" ) )

if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='Pyiptanalyzer')
    parser.add_argument('-c', action = "store", dest = "cache_file")
    parser.add_argument('-o', action = "store", dest = "output")

    args = parser.parse_args()

    merger = Merger()
    merger.read_directory(args.cache_file)
    merger.write(args.output)