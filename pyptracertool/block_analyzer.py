import os
import pprint
import pickle

import capstone

import decoder
import windbgtool.debugger

class BlockAnalyzer:
    def __init__(self, cache_dirname, pt_filename, dump_filename):
        self.PTFilename = pt_filename
        self.DumpFilename = dump_filename
        self.BlockIPMap = {}
        self.LoadedModules = {}
        self.AddressToSymbols = {}
        self.SymbolsToAddress = {}

        self.ReadDirectory(cache_dirname)

        self.Debugger = windbgtool.debugger.DbgEngine()
        self.Debugger.LoadDump(dump_filename)
        self.Debugger.EnumerateModules()       
        self.ResolveSymbols()

    def DumpSymbols(self, symbol):
        if not symbol in self.SymbolsToAddress:
            return

        address = self.SymbolsToAddress[symbol]
        for start_offset in self.BlockIPMap[address]:
            print('start_offset = %x' % (start_offset))

            """
            pytracer = decoder.PTLogAnalyzer(self.PTFilename, 
                                             self.DumpFilename, 
                                             dump_symbols = True, 
                                             load_image = True, 
                                             start_offset = start_offset, end_offset = start_offset + 1024*10)
            pytracer.DecodeInstruction()
            """

    def FindOffsets(self, symbol):
        for block_address in self.BlockAddresses.keys():
            if block_address in self.AddressToSymbols:
                print(self.AddressToSymbols[block_address])

    def LoadModuleSymbols(self, module_name):
        if module_name in self.LoadedModules:
            return
        self.LoadedModules[module_name] = True

        print('LoadModuleSymbols: ' + module_name)
        for (address, symbol) in self.Debugger.EnumerateModuleSymbols([module_name, ]).items():
            self.AddressToSymbols[address] = symbol
            self.SymbolsToAddress[symbol] = address

    def LoadSymbols(self, address):
        address_info = self.Debugger.GetAddressInfo(address)
        if address_info and 'Module Name' in address_info:
            self.LoadModuleSymbols(address_info['Module Name'])

    def ResolveSymbols(self):
        for block_address in self.BlockIPMap.keys():
            self.LoadSymbols(block_address)

    def ReadDirectory(self, dirname):
        for basename in os.listdir(dirname):
            if not basename.endswith('.p'):
                continue
            self.Read(os.path.join(dirname, basename))

    def Read(self, filename):
        for (address, offsets) in pickle.load(open(filename, "rb")).items():
            if not address in self.BlockIPMap:
                self.BlockIPMap[address] = []

            for offset in offsets:
                self.BlockIPMap[address].append(offset)
    
if __name__ == '__main__':
    cache_folder = 'Tmp'
    pt_filename = '../TestFiles/trace.pt'
    dump_filename = '../TestFiles/notepad.exe.dmp'
    block_analyzer = BlockAnalyzer(cache_folder, pt_filename, dump_filename)
    block_analyzer.DumpSymbols('KERNELBASE!CreateFileW')