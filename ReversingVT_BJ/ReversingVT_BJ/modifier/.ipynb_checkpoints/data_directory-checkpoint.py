import lief
import random

def pert_data_directory(fbytes):
    random.seed(None)
    fparsed = lief.parse(fbytes)

    target = random.choice(fparsed.data_directories)

    target.rva = random.randrange(0,2**32)
    target.size = random.randrange(0,2**32)

    return fparsed
