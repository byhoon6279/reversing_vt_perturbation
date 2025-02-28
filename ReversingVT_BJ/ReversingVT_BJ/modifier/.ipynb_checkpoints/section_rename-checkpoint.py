import lief
import pefile
import random

def section_rename(fbytes):
    random.seed(None)
    length = random.randrange(1,6)
    fparsed = lief.parse(fbytes)
    name = "."+''.join(random.sample([chr(i) for i in range(97,123)], length))
    #print(name)
    targeted_section = random.choice(fparsed.sections)
    targeted_section.name = name
    
    return fparsed
