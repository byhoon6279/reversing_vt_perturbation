import lief

def pert_rich_header(fbytes): # add rich header entry
    fparsed = lief.parse(fbytes)
    new_entry = lief.PE.RichEntry()
    new_entry.id = 101
    new_entry.build_id = 0x766f
    new_entry.count = 2

    fparsed.rich_header.add_entry(new_entry)

    return fparsed

