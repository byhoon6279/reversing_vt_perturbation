import lief
import random

def pert_coff_header(fbytes):
    random.seed(None)
    fparsed = lief.parse(fbytes)

    fparsed.header.numberof_symbols = random.randrange(0,2**32)
    fparsed.header.time_date_stamps = random.randrange(0,2**32)
    fparsed.header.pointerto_symbol_table = random.randrange(0,2**32)

    return fparsed
