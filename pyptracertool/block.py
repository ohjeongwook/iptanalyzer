import os
import pprint
import pickle

import capstone

import decoder
import windbgtool.debugger

class Analyzer:
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

    def DumpInstructions(self, start_offset, end_offset, instruction_offset):
        pytracer = decoder.PTLogAnalyzer(self.PTFilename, 
                                            self.DumpFilename, 
                                            dump_symbols = False, 
                                            load_image = True, 
                                            start_offset = start_offset, 
                                            end_offset = start_offset + 1024*10)

        for insn in pytracer.DecodeInstruction(move_forward = False, instruction_offset = instruction_offset):
            disasmline = pytracer.GetDisasmLine(insn)
            print('Instruction: %s' % (disasmline))

    def _NormalizeSymbol(self, symbol):
        (module, function) = symbol.split('!')
        return module.lower() + '!' + function

    def DumpSymbolLocations(self, symbol, dump_instructions = False):
        symbol = self._NormalizeSymbol(symbol)
        if not symbol in self.SymbolsToAddress:
            print('Symbol [%s] is not found' % (symbol))
            return

        address = self.SymbolsToAddress[symbol]
        print('Searching %s: %x' % (symbol, address))

        if not address in self.BlockIPMap:
            return

        for sync_offset in self.BlockIPMap[address]:
            for offset in self.BlockIPMap[address][sync_offset]:
                print('> sync_offset = %x / offset = %x' % (sync_offset, offset))

                if dump_instructions:
                    self.DumpInstructions(sync_offset, offset+1, offset)

    def FindOffsets(self, symbol):
        for block_address in self.BlockAddresses.keys():
            if block_address in self.AddressToSymbols:
                print(self.AddressToSymbols[block_address])

    def LoadModuleSymbols(self, module_name):
        module_name = module_name.lower()
        if module_name in self.LoadedModules:
            return

        for (address, symbol) in self.Debugger.EnumerateModuleSymbols([module_name, ]).items():
            symbol = self._NormalizeSymbol(symbol)
            self.AddressToSymbols[address] = symbol
            self.SymbolsToAddress[symbol] = address

        self.LoadedModules[module_name] = True

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
        for (address, offset_map) in pickle.load(open(filename, "rb")).items():
            if not address in self.BlockIPMap:
                self.BlockIPMap[address] = {}

            for (sync_offset, v) in offset_map.items():
                if not sync_offset in self.BlockIPMap[address]:
                    self.BlockIPMap[address][sync_offset] = {}

                for (offset, v2) in v.items():
                    self.BlockIPMap[address][sync_offset][offset] = v