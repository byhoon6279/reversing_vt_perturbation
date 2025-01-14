import os

def overlay_append_dummy(data: bytes, overlay_contents: bytes = None) -> bytes:
    # Append random overlay data at the end of the PE file
    if overlay_contents is None:
        return data + os.urandom(0x1000)
    return data + overlay_contents
