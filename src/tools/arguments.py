
def auto_int(x):
    return int(x, 0)

def add_arguments(parser):
    parser.add_argument('-p', dest = "pt_filename", default = "", metavar = "<PT filename>", help = "Intel PT trace filename", required=True)
    parser.add_argument('-d', dest = "dump_filename", metavar = "<process dump filename>", help = "Process dump filename", required=True)
    parser.add_argument('-c', dest = "cache_filename", metavar = "<cache filename>", help = "Cache filename", required=True)
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int, metavar = "<cr3>", help = "CR3 value to include (cr3 is associated with unique process)")

    parser.add_argument('-D', dest = "debug_level", default = 0, type = auto_int, metavar = "<debug level>", help = "Debug level")
    parser.add_argument('-O', dest = "debug_filename", default = "stdout", metavar = "<debug filename>", help = "Debug filename")
    
def add_address_range_arguments(parser):
    parser.add_argument('-s', dest = "start_address", default = 0, type = auto_int, metavar = "<start address>", help = "Start address to include")
    parser.add_argument('-e', dest = "end_address", default = 0, type = auto_int, metavar = "<end address>", help = "End address to include")

def add_module_arguments(parser):
    parser.add_argument('-m', dest = "module_name",  default = "", metavar = "<module name>", help = "Module name to dump")

def add_offset_range_arguments(parser):
    parser.add_argument('-S', dest = "start_offset", default = 0, type = auto_int, metavar = "<start offset>", help = "Start offset in the file")
    parser.add_argument('-E', dest = "end_offset", default = 0, type = auto_int, metavar = "<end offset>", help = "End offset in the file")
