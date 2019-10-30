import pprint
import pickle

block_offsets = pickle.load(open("BlockOffsets.p", "rb"))

pprint.pprint(block_offsets)