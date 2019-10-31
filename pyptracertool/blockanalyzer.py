import os
import pprint
import pickle

import capstone

import pyptracertool
import windbgtool.debugger

class BlockAnalyzer:
    def __init__(self, cache_dirname, dump_filename):
        self.BlockAddresses = {}
        self.ReadDirectory(cache_dirname)
        print(len(self.BlockAddresses))

        self.Debugger = windbgtool.debugger.DbgEngine()
        self.Debugger.LoadDump(dump_filename)
        self.Debugger.EnumerateModules()

        self.Modules = {}
        self.AddressToSymbols = {}
        self.SymbolsToAddress = {}
        self.ResolveSymbols()

    def DumpSymbols(self, symbol):
        if not symbol in self.SymbolsToAddress:
            return

        address = self.SymbolsToAddress[symbol]

        for offset in self.BlockAddresses[address]:
            print('offset = %x' % (offset))

    def FindOffsets(self, symbol):
        for block_address in self.BlockAddresses.keys():
            if block_address in self.AddressToSymbols:
                print(self.AddressToSymbols[block_address])

    def LoadModuleSymbols(self, module_name):
        if module_name in self.Modules:
            return

        self.Modules[module_name] = True

        print('LoadModuleSymbols: ' + module_name)
        for (address, symbol) in self.Debugger.EnumerateModuleSymbols([module_name, ]).items():
            self.AddressToSymbols[address] = symbol
            self.SymbolsToAddress[symbol] = address

    def LoadSymbols(self, address):
        address_info = self.Debugger.GetAddressInfo(address)
        if address_info and 'Module Name' in address_info:
            self.LoadModuleSymbols(address_info['Module Name'])

    def ResolveSymbols(self):
        for block_address in self.BlockAddresses.keys():
            self.LoadSymbols(block_address)

    def ReadDirectory(self, dirname):
        for basename in os.listdir(dirname):
            if not basename.endswith('.p'):
                continue
            self.Read(os.path.join(dirname, basename))

    def Read(self, filename):
        print(filename)

        block_offsets = pickle.load(open(filename, "rb"))

        for (address, offsets) in block_offsets.items():
            if not address in self.BlockAddresses:
                self.BlockAddresses[address] = 1
            else:
                self.BlockAddresses[address] += 1

    
if __name__ == '__main__':
    cache_folder = 'Tmp'
    dump_filename = '../TestFiles/notepad.exe.dmp'
    block_analyzer = BlockAnalyzer(cache_folder, dump_filename)
    block_analyzer.DumpSymbols('KERNELBASE!CreateFileW')