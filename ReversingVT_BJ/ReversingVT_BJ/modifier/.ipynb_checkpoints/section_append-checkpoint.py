import pefile
import os

def section_append_unused(data: bytes) -> bytes:
    data = bytearray(data)
    pe = pefile.PE(data=data)

    # Find and fill unused space in sections with random bytes
    for section in pe.sections:
        if section.SizeOfRawData > section.Misc_VirtualSize:
            offset = section.PointerToRawData + section.Misc_VirtualSize
            size = section.SizeOfRawData - section.Misc_VirtualSize

            pe.__data__[offset : offset + size] = os.urandom(size)

    return data


def section_append_gap(data:bytes) -> bytes:
    data = bytearray(data)
    pe = pefile.PE(data=data)

    # find and fill gap between sections with random bytes
    for i in range(1, len(pe.sections)):
        offset = pe.sections[i-1].PointerToRawData + pe.sections[i-1].SizeOfRawData
        size = pe.sections[i].PointerToRawData - offset

        # 🔹 size가 0 이하일 경우 무시
        if size <= 0:
            section_name = pe.sections[i].Name.decode('utf-8', errors='ignore').strip('\x00')

            # 🔹 오프셋 값 & 크기 출력
            print(f"Warning: Skipping section [{section_name}] due to invalid size ({size})")
            continue

        pe.__data__[offset : offset + size] = os.urandom(size)
    
    return data


# Test code
if __name__ == "__main__":
    data = open("putty.exe", "rb").read()
    data = section_append_unused(data)
    data = section_append_gap(data)
    open("fake.exe", "wb").write(data)