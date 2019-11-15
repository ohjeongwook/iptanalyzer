import os
import pprint
import pickle

class CacheReader:
    def __init__(self, cache_filename, pt_filename):
        self.PTFilename = pt_filename
        [self.BlockIPsToOffsets, self.BlockOffsetsToIPs] = pickle.load(open(cache_filename, "rb"))

    def EnumerateBlockRange(self, cr3 = 0, start_address = 0, end_address = 0):
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

    def EnumerateBlocks(self, address = None, cr3 = 0):
        if not cr3 in self.BlockIPsToOffsets:
            return

        print('Searching Block Addresss: %x' % (address))
        if not address in self.BlockIPsToOffsets[cr3]:
            return

        for sync_offset in self.BlockIPsToOffsets[cr3][address]:
            for offset in self.BlockIPsToOffsets[cr3][address][sync_offset]:
                yield (sync_offset, offset)

    def FindOffsets(self, symbol):
        for block_address in self.BlockAddresses.keys():
            if block_address in self.AddressToSymbols:
                print(self.AddressToSymbols[block_address])

