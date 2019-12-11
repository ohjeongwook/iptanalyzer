import windbgtool.debugger

class Loader:
    def __init__(self, dump_filename):
        self.DumpFilename = dump_filename
        self.LoadedModules = {}
        self.AddressToSymbols = {}
        self.SymbolsToAddress = {}

        self.Debugger = windbgtool.debugger.DbgEngine()
        self.Debugger.LoadDump(self.DumpFilename)
        self.Debugger.EnumerateModules()
    
    def __normalize_symbol(self, symbol):
        (module, function) = symbol.split('!', 1)
        return module.lower() + '!' + function

    def load_module_symbols(self, module_name):
        module_name = module_name.split('.')[0]
        module_name = module_name.lower()
        if module_name in self.LoadedModules:
            return

        for (address, symbol) in self.Debugger.EnumerateModuleSymbols([module_name, ]).items():
            symbol = self.__normalize_symbol(symbol)
            self.AddressToSymbols[address] = symbol
            self.SymbolsToAddress[symbol] = address

        self.LoadedModules[module_name] = True

    def load_address_symbol(self, address):
        address_info = self.Debugger.GetAddressInfo(address)
        if address_info and 'Module Name' in address_info:
            self.load_module_symbols(address_info['Module Name'])

    def get_symbol(self, address):
        if address in self.AddressToSymbols:
            symbol = self.AddressToSymbols[address]
        else:
            self.load_address_symbol(address)
            if address in self.AddressToSymbols:
                symbol = self.AddressToSymbols[address]
            else:
                symbol = ''
        return symbol

    def resolve_symbol_address(self, symbol_str):
        symbol_str = self.__normalize_symbol(symbol_str)

        module_name = symbol_str.split('!')[0]
        self.load_module_symbols(module_name)

        if not symbol_str in self.SymbolsToAddress:
            print('Symbol [%s] is not found' % (symbol_str))
            return None

        address = self.SymbolsToAddress[symbol_str]
        print('Searching %s: %x' % (symbol_str, address))

        return address

    def get_disassembly_line(self, ip):
        try:
            return self.Debugger.RunCmd('u %x L1' % (ip))
        except:
            return ''
