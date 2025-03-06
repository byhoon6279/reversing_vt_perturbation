import sys
import os
import lief
from intelhex import IntelHex

def check_overlay(data):
    print (data[-4:].hex())

def check_header(fparsed):
    print ("="*10+"Checksum info"+"="*10)
    print("Checksum:", fparsed.optional_header.checksum)

    print ("\n", "="*10+"Debug info"+"="*10)
    for dbg in fparsed.data_directories:
        if str(dbg.type) == "DATA_DIRECTORY.DEBUG":
            print (dbg)
    
    print ("="*10+"Section name info"+"="*10)
    for section in fparsed.sections:
        print (section.name)

def check_slack():
    b1 = open("test/sample2.exe","rb").read()
    b2 = open("test/changed_sample2.exe","rb").read()

def check_dos_header(fparsed):
    print (fparsed.dos_header)
    print (list(fparsed.dos_stub))

def check_add_section(fparsed):
    for section in fparsed.sections:
        print (list(section.content))


_input = sys.argv[1]

data  = open(_input,"rb").read()
fparsed = lief.parse(data)

# check_header(fparsed)
# check_slack()
# check_dos_header(fparsed)
# check_add_section(fparsed)




