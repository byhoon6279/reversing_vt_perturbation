import lief

# def pert_rich_header(fbytes): # add rich header entry
#     fparsed = lief.parse(fbytes)
#     new_entry = lief.PE.RichEntry()
#     new_entry.id = 101
#     new_entry.build_id = 0x766f
#     new_entry.count = 2

#     fparsed.rich_header.add_entry(new_entry)

#     return fparsed

def pert_rich_header(filepath):
    fparsed = lief.parse(filepath)

    if fparsed is None:
        print("❌ Error: Failed to parse the PE file!")
        return None

    if fparsed.rich_header is None:
        print("⚠️ Warning: No Rich Header found. Creating a new one.")
        fparsed.rich_header = lief.PE.RichHeader()

    # 새로운 Rich Entry 추가
    new_entry = lief.PE.RichEntry()
    new_entry.id = 101
    new_entry.build_id = 0x766f
    new_entry.count = 2

    fparsed.rich_header.add_entry(new_entry)
    
    return fparsed