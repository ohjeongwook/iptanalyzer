import os
import pprint
import pickle

class Writer:
    def __init__(self, basic_block_addresss_to_offsets, block_offsets_to_ips):
        self.basic_block_addresss_to_offset = basic_block_addresss_to_offsets
        self.block_offsets_to_ips = block_offsets_to_ips

    def save(self, filename):
        pickle.dump([self.basic_block_addresss_to_offset, self.block_offsets_to_ips], open(filename, "wb" ) )

class Reader:
    def __init__(self, cache_filename, pt_filename):
        self.PTFilename = pt_filename
        [self.basic_block_addresss_to_offset, self.block_offsets_to_ips] = pickle.load(open(cache_filename, "rb"))

    def enumerate_block_range(self, cr3 = 0, start_address = 0, end_address = 0):
        if not cr3 in self.block_offsets_to_ips:
            return

        offsets = list(self.block_offsets_to_ips[cr3].keys())            
        offsets.sort()

        for offset in offsets:
            for block in self.block_offsets_to_ips[cr3][offset]:
                block_start = block['IP']
                block_end = block['EndIP']
                if start_address > 0 and end_address > 0:
                    if block_start >= start_address and block_start <= end_address:
                        yield (offset, block)

                    if block_end >= start_address and block_end <= end_address:
                        yield (offset, block)

    def enumerate_blocks(self, address = None, cr3 = 0):
        if not cr3 in self.basic_block_addresss_to_offset:
            return

        print('Searching Block Addresss: %x' % (address))
        if not address in self.basic_block_addresss_to_offset[cr3]:
            return

        for sync_offset in self.basic_block_addresss_to_offset[cr3][address]:
            for offset in self.basic_block_addresss_to_offset[cr3][address][sync_offset]:
                yield (sync_offset, offset)

    def find_offsets(self, symbol):
        for block_address in self.BlockAddresses.keys():
            if block_address in self.AddressToSymbols:
                print(self.AddressToSymbols[block_address])

class Merger:
    def __init__(self):
        self.basic_block_addresss_to_offset = {}
        self.block_offsets_to_ips = {}

    def read_directory(self, dirname):
        for basename in os.listdir(dirname):
            if not basename.endswith('.cache'):
                continue
            self.read(os.path.join(dirname, basename))

    def read(self, filename):
        try:
            [basic_block_addresss_to_offset, block_offsets_to_ips] = pickle.load(open(filename, "rb"))
        except:
            print("Error loading " + filename)
            return

        for (cr3, address_to_offsets) in basic_block_addresss_to_offset.items():
            if not cr3 in self.basic_block_addresss_to_offset:
                self.basic_block_addresss_to_offset[cr3] = {}

            for (address, offset_map) in address_to_offsets.items():
                if not address in self.basic_block_addresss_to_offset[cr3]:
                    self.basic_block_addresss_to_offset[cr3][address] = {}

                for (sync_offset, v) in offset_map.items():
                    if not sync_offset in self.basic_block_addresss_to_offset[cr3][address]:
                        self.basic_block_addresss_to_offset[cr3][address][sync_offset] = {}

                    for (offset, v2) in v.items():
                        self.basic_block_addresss_to_offset[cr3][address][sync_offset][offset] = v

        for (cr3, offsets_to_addresses) in block_offsets_to_ips.items():
            if not cr3 in self.block_offsets_to_ips:
                self.block_offsets_to_ips[cr3] = {}

            for (offset, addresses) in offsets_to_addresses.items():
                if not offset in self.block_offsets_to_ips[cr3]:
                    self.block_offsets_to_ips[cr3][offset] = []

                for address in addresses:
                    self.block_offsets_to_ips[cr3][offset].append(address)

    def write(self, filename):
        pickle.dump([self.basic_block_addresss_to_offset, self.block_offsets_to_ips], open(filename, "wb" ) )

if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-c', action = "store", dest = "cache_file")
    parser.add_argument('-o', action = "store", dest = "output")

    args = parser.parse_args()

    merger = Merger()
    merger.read_directory(args.cache_file)
    merger.write(args.output)