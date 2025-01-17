import os
import sys
import random
import lief
import pefile
sys.path.append("modifier")

from overlay_append import *
from perturb_pe_header import *
from modify_dos_header import *
from extend_dos_header import *
from dropper import *
from entry_point_extend import *
from code_randomization import *
from jmp_back_to_other_address import *
from add_section import *
from change_entrypoint import *
from entry_point_extend import *
from nop_insertion import *
from packing import *
from section_append import *
from filling_slack import *
from contents_shifting import *
from import_function_injection import *
from section_rename import *
from rich_header import *
from pert_optional_header import *
from coff_header import *
from data_directory import *
from instruction_change import *
from resource_change import *
from increase_section import *

class Modifier:
    def __init__(self, sample_path, opath):
        self.sample_path = sample_path
        if "/" in sample_path:
            self.sample = sample_path[sample_path.rindex("/")+1:]
            self.root_sample = sample_path.replace(self.sample,"")
        else:
            self.sample = sample_path
            self.root_sample = "./"

        self.data = open(sample_path, "rb").read()
        self.opath = opath

    def build_lief_name(self, fparsed, pertname):
        pe = pefile.PE(self.sample_path)
        # fparsed = lief.parse(fbytes)
        builder = lief.PE.Builder(fparsed)
        builder.build()
        new_fname = "{}/{}_{}.exe".format(self.opath, self.sample[:-4], pertname)
        builder.write(new_fname)

        pe2 = pefile.PE(new_fname)

        if pe.OPTIONAL_HEADER.SizeOfHeaders != pe2.OPTIONAL_HEADER.SizeOfHeaders:
            pe2.OPTIONAL_HEADER.SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders

        pe2.write(new_fname)

    def overlay_append(self):
        append_data = os.urandom(0x1000)
        new_data = overlay_append_dummy(self.data, append_data)
        open("{}/{}_overlay_append.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def section_rename(self):
        length = random.randrange(1,10)
        section_name ="."+''.join(random.sample([chr(i) for i in range(97,123)], length))
        checksum = os.urandom(0x4) # b"\x01\x02\x03\x04"
        new_data = perturb_pe_header(self.data, section_name, checksum)
        open("{}/{}_section_rename.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def fill_slack_space(self):
        new_data = fill_slack(self.data)
        open("{}/{}_perturb_header.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def modify_dos_header(self):
        new_data = modify_dos_header(self.data)
        open("{}/{}_modify_dos_header.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def dos_stub(self):
        code = os.urandom(0xA00)
        new_data = extend_dos_stub(self.data, code)
        open("{}/{}_modify_dos_stub.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def content_shifting(self):
        new_data = gap_sections(self.data)
        new_data = extend_and_shift_sections(new_data)
        open("{}/{}_content_shifting.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def inject_import_func(self): 
        # Does not work
        arbitrary_code = b"\xcc" * 0x100
        value = [
            {"funcname" : b"GetProcAddress", "nativecode" : b"\xcc" * 0x100},
            {"funcname" : b"GetCurrentThreadId", "nativecode" : b"\x90" * 0x100},
        ]
        new_data = iat_injection(self.data, value)
        open("{}/{}_inject_import_func.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def section_add(self):
        _data = bytearray(self.data)
        length = random.randrange(1,10)
        section_name ="."+''.join(random.sample([chr(i) for i in range(97,123)], length))
        content = os.urandom(0x100)
        new_data = add_section(_data, section_name, content, PERM.READ | PERM.WRITE | PERM.EXEC)
        open("{}/{}_section_add.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def section_append(self):
        new_data = section_append_unused(self.data)
        new_data = section_append_gap(self.data)
        open("{}/{}_section_append.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def packing(self):
        output_exe_path = "{}/{}_packing.exe".format(self.opath, self.sample[:-4])
        pack_with_upx(self.sample_path, output_exe_path)

    
    def code_randomization(self):
        _data = bytearray(self.data)
        new_data = code_randomization(_data)
        open("{}/{}_code_randomization.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def change_entrypoint(self):
        # Does not work
        _data = bytearray(self.data)
        new_data = change_entry_point(_data, 0xdeadbeef)
        open("{}/{}_change_entrypoint.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def dropper(self):
        # Does not work
        '''
        _data = bytearray(self.data)
        drop_binary = bytearray(open("test/hello_world.exe", "rb").read())
        new_data = dropper(_data, drop_binary, b"C:\\tmp\\test.exe")
        open("{}/{}_dropper.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)
        '''
        pass
    
    def extend_entrypoint(self):
        # Does not work
        _data = bytearray(self.data)
        new_data = entry_point_extend(_data, '.tls', 0x1234, 0xdeadbeef)
        open("{}/{}_extend_entrypoint.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def nop_insertion(self):
        _data = bytearray(self.data)
        new_data = nop_insertion(_data, 2)
        open("{}/{}_nop_insertion.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def jmp_overlay_back(self):
        fparsed = lief.parse(self.data)
        _data = bytearray(self.data)
        overlay_addr = len(self.data)+fparsed.optional_header.baseof_code
        _data = overlay_append_dummy(_data, itob4(0x40105c))
        code_base = fparsed.optional_header.imagebase+fparsed.optional_header.baseof_code
#         new_data = jmp_back_to_other_address(_data, 0x401000, overlay_addr)
        new_data = jmp_back_to_other_address(_data, code_base, overlay_addr)
        open("{}/{}_jmp_overlay_back.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)
    
    def section_rename(self):
        fparsed = section_rename(self.data)
        self.build_lief_name(fparsed,"section_rename")
    
    def rich_header(self):
        fparsed = pert_rich_header(self.data)
        self.build_lief_name(fparsed,"rich_header")

    def optional_header(self):
        fparsed = pert_optional_header(self.data)
        self.build_lief_name(fparsed,"optional_header")

    def coff_header(self):
        fparsed = pert_coff_header(self.data)
        self.build_lief_name(fparsed,"coff_header")

    def data_directory(self):
        fparsed = pert_data_directory(self.data)
        self.build_lief_name(fparsed,"data_directory")

    def instruction_change(self):
        args = (self.sample, self.root_sample, self.opath)
        instruction_change(args)

    def resource_change(self):
        args = (self.sample, self.root_sample, self.opath)
        resource_change(args)

    def increase_section(self):
        args = (self.sample, self.root_sample, self.opath)
        increase_section(args)


