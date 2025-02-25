# Copyright (c) 2021, Mahmood Sharif, Keane Lucas, Michael K. Reiter, Lujo Bauer, and Saurabh Shintre
# This file is code used in Malware Makeover

"""
used for creating semantic nops
"""
import struct
import random

ATOM_NOP_1B = [b'\x90'] # nop
ATOM_NOP_2B = [b'\x88\xc0', # mov al, al
               b'\x88\xe4', # mov eah, eah
               b'\x89\xc0', # mov eax, eax
               b'\x88\xdb', # mov bl, bl
               b'\x88\xff', # mov bh, bh
               b'\x89\xdb', # mov ebx, ebx
               b'\x88\xc9', # mov cl, cl
               b'\x88\xed', # mov ch, ch
               b'\x89\xc9', # mov ecx, ecx
               b'\x88\xd2', # mov dl, dl,
               b'\x88\xf6', # mov dh, dh
               b'\x89\xd2'] # mov edx, edx
ATOM_NOP_3B = [b'\x66\x89\xc0', # mov ax, ax
               b'\x66\x89\xdb', # mov bx, bx
               b'\x66\x89\xc9', # mov cx, cx
               b'\x66\x89\xd2'] # mov dx, dx

def atomic_nop(n_bytes):
    """
    A single instruction nop
    """
    global ATOM_NOP_1B, ATOM_NOP_2B, ATOM_NOP_3B
    if n_bytes==1:
        return random.choice(ATOM_NOP_1B).decode('latin1')
    elif n_bytes==2:
        return random.choice(ATOM_NOP_2B).decode('latin1')
    elif n_bytes==3:
        return random.choice(ATOM_NOP_3B).decode('latin1')
    else:
        raise ValueError('n_bytes should be in {1,2,3}')

def combo_nop():
    """
    an operation and its reverse that do not affect any
    register or memory:
    bswp regx; bswp regx
    or
    xchg reg_low, reg_h; xchg reg_low, reg_h
    """
    reg = random.choice(['eax', 'ebx', 'ecx', 'edx'])
    combo_type = random.choice(['bswp', 'xchg_l2h', 'xchg_h2l'])
    if combo_type=='bswp':
        if reg=='eax':
            return b'\x0f\xc8', b'\x0f\xc8'
        if reg=='ebx':
            return b'\x0f\xcb', b'\x0f\xcb'
        if reg=='ecx':
            return b'\x0f\xc9', b'\x0f\xc9'
        if reg=='edx':
            return b'\x0f\xca', b'\x0f\xca'
    if combo_type=='xchg_l2h':
        if reg=='eax':
            return b'\x86\xe0', b'\x86\xe0'
        if reg=='ebx':
            return b'\x86\xfb', b'\x86\xfb'
        if reg=='ecx':
            return b'\x86\xe9', b'\x86\xe9'
        if reg=='edx':
            return b'\x86\xf2', b'\x86\xf2'
    if combo_type=='xchg_h2l':
        if reg=='eax':
            return b'\x86\xc4', b'\x86\xc4'
        if reg=='ebx':
            return b'\x86\xdf', b'\x86\xdf'
        if reg=='ecx':
            return b'\x86\xcd', b'\x86\xcd'
        if reg=='edx':
            return b'\x86\xd6', b'\x86\xd6'
    else:
        raise Exception('unexpected error')

def ef_altering_nop(n_bytes):
    """
    A nop that may alter the flags register, but
    not others.
    """
    assert(n_bytes>0), 'n_bytes has to be positive'
    
    options = [(b'\xf9', '')]     # stc
    options.append((b'\xf8', '')) # clc
    
    if n_bytes>=2:
        # comparisons
        options.append((b'\x39\xD8', '')) # cmp eax, ebx
        options.append((b'\x39\xC8', '')) # cmp eax, ecx
        options.append((b'\x39\xD0', '')) # cmp eax, edx
        options.append((b'\x39\xC3', '')) # cmp ebx, eax
        options.append((b'\x39\xCB', '')) # cmp ebx, ecx
        options.append((b'\x39\xD3', '')) # cmp ebx, edx
        options.append((b'\x39\xC1', '')) # cmp ecx, eax
        options.append((b'\x39\xD9', '')) # cmp ecx, ebx
        options.append((b'\x39\xD1', '')) # cmp ecx, edx
        options.append((b'\x39\xC2', '')) # cmp edx, eax
        options.append((b'\x39\xDA', '')) # cmp edx, ebx
        options.append((b'\x39\xCA', '')) # cmp edx, ecx
        options.append((b'\x38\xD8', '')) # cmp al, bl
        options.append((b'\x38\xC8', '')) # cmp al, cl
        options.append((b'\x38\xD0', '')) # cmp al, dl
        options.append((b'\x38\xE0', '')) # cmp al, ah
        options.append((b'\x38\xF8', '')) # cmp al, bh
        options.append((b'\x38\xE8', '')) # cmp al, ch
        options.append((b'\x38\xF0', '')) # cmp al, dh
        options.append((b'\x38\xC3', '')) # cmp bl, al
        options.append((b'\x38\xCB', '')) # cmp bl, cl
        options.append((b'\x38\xD3', '')) # cmp bl, dl
        options.append((b'\x38\xE3', '')) # cmp bl, ah
        options.append((b'\x38\xFB', '')) # cmp bl, bh
        options.append((b'\x38\xEB', '')) # cmp bl, ch
        options.append((b'\x38\xF3', '')) # cmp bl, dh
        options.append((b'\x38\xC1', '')) # cmp cl, al
        options.append((b'\x38\xD9', '')) # cmp cl, bl
        options.append((b'\x38\xD1', '')) # cmp cl, dl
        options.append((b'\x38\xE1', '')) # cmp cl, ah
        options.append((b'\x38\xF9', '')) # cmp cl, bh
        options.append((b'\x38\xE9', '')) # cmp cl, ch
        options.append((b'\x38\xF1', '')) # cmp cl, dh
        options.append((b'\x38\xC2', '')) # cmp dl, al
        options.append((b'\x38\xDA', '')) # cmp dl, bl
        options.append((b'\x38\xCA', '')) # cmp dl, cl
        options.append((b'\x38\xE2', '')) # cmp dl, ah
        options.append((b'\x38\xFA', '')) # cmp dl, bh
        options.append((b'\x38\xEA', '')) # cmp dl, ch
        options.append((b'\x38\xF2', '')) # cmp dl, dh
        # al+0 or al-0
        options.append((b'\x04\x00', '')) # add al, 0
        options.append((b'\x2C\x00', '')) # sub al, 0
        # inc reg, ..., dec reg (or vice versa)
        options.append((b'\x40', b'\x48')) # inc eax; ...; dec eax
        options.append((b'\x48', b'\x40'))
        options.append((b'\x43', b'\x4B')) # inc ebx; ...; dec ebx
        options.append((b'\x4B', b'\x43'))
        options.append((b'\x41', b'\x49')) # inc ecx; ...; dec ecx
        options.append((b'\x49', b'\x41'))
        options.append((b'\x42', b'\x4A')) # inc edx; ...; dec edx
        options.append((b'\x4A', b'\x42'))
        # logical stuff
        options.append((b'\x20\xC0', '')) # and al, al
        options.append((b'\x20\xE4', '')) # and ah, ah
        options.append((b'\x21\xC0', '')) # and eax, eax
        options.append((b'\x08\xC0', '')) # or al, al
        options.append((b'\x08\xE4', '')) # or ah, ah
        options.append((b'\x09\xC0', '')) # or eax, eax
        options.append((b'\x84\xC0', '')) # test al, al
        options.append((b'\x84\xE4', '')) # test ah, ah
        options.append((b'\x85\xC0', '')) # test eax, eax
        options.append((b'\x20\xDB', '')) # and bl, bl
        options.append((b'\x20\xFF', '')) # and bh, bh
        options.append((b'\x21\xDB', '')) # and ebx, ebx
        options.append((b'\x08\xDB', '')) # or bl, bl
        options.append((b'\x08\xFF', '')) # or bh, bh
        options.append((b'\x09\xDB', '')) # or ebx, ebx
        options.append((b'\x84\xDB', '')) # test bl, bl
        options.append((b'\x84\xFF', '')) # test bh, bh
        options.append((b'\x85\xDB', '')) # test ebx, ebx
        options.append((b'\x20\xC9', '')) # and cl, cl
        options.append((b'\x20\xED', '')) # and ch, ch
        options.append((b'\x21\xC9', '')) # and ecx, ecx
        options.append((b'\x08\xC9', '')) # or cl, cl
        options.append((b'\x08\xED', '')) # or ch, ch
        options.append((b'\x09\xC9', '')) # or ecx, ecx
        options.append((b'\x84\xC9', '')) # test cl, cl
        options.append((b'\x84\xED', '')) # test ch, ch
        options.append((b'\x86\xC9', '')) # test ecx, ecx
        options.append((b'\x20\xD2', '')) # and dl, dl
        options.append((b'\x20\xF6', '')) # and dh, dh
        options.append((b'\x21\xD2', '')) # and edx, edx
        options.append((b'\x08\xD2', '')) # or dl, dl
        options.append((b'\x08\xF6', '')) # or dh, dh
        options.append((b'\x09\xD2', '')) # or edx, edx
        options.append((b'\x84\xD2', '')) # test dl, dl
        options.append((b'\x84\xF6', '')) # test dh, dh
        options.append((b'\x85\xD2', '')) # test edx, edx

    if n_bytes>=3:
        # add/sub 0s
        options.append((b'\x80\xC4\x00', '')) # add ah, 0
        options.append((b'\x83\xC0\x00', '')) # add eax, 0
        options.append((b'\x80\xC3\x00', '')) # add bl, 0
        options.append((b'\x80\xC7\x00', '')) # add bh, 0
        options.append((b'\x83\xC3\x00', '')) # add ebx, 0
        options.append((b'\x80\xC1\x00', '')) # add cl, 0
        options.append((b'\x80\xC5\x00', '')) # add ch, 0
        options.append((b'\x83\xC1\x00', '')) # add ecx, 0
        options.append((b'\x80\xC2\x00', '')) # add dl, 0
        options.append((b'\x80\xC6\x00', '')) # add dh, 0
        options.append((b'\x83\xC2\x00', '')) # add edx, 0
        options.append((b'\x80\xEC\x00', '')) # sub ah, 0
        options.append((b'\x83\xE8\x00', '')) # sub eax, 0
        options.append((b'\x80\xEB\x00', '')) # sub bl, 0
        options.append((b'\x80\xEF\x00', '')) # sub bh, 0
        options.append((b'\x83\xEB\x00', '')) # sub ebx, 0
        options.append((b'\x80\xE9\x00', '')) # sub cl, 0
        options.append((b'\x80\xED\x00', '')) # sub ch, 0
        options.append((b'\x83\xE9\x00', '')) # sub ecx, 0
        options.append((b'\x80\xEA\x00', '')) # sub dl, 0
        options.append((b'\x80\xEE\x00', '')) # sub dh, 0
        options.append((b'\x83\xEA\x00', '')) # sub edx, 0

    if n_bytes>=4:
        # rol reg; ...; ror reg (or vice versa)
        options.append((b'\xD1\xC0', b'\xD1\xC8')) # rol eax; ror eax
        options.append((b'\xD0\xC0', b'\xD0\xC8')) # rol al; ror al
        options.append((b'\xD0\xC4', b'\xD0\xCC')) # rol ah; ror ah
        options.append((b'\xD1\xC8', b'\xD1\xC0')) # ror eax; rol eax
        options.append((b'\xD0\xC8', b'\xD0\xC0')) # ror al; rol al
        options.append((b'\xD0\xCC', b'\xD0\xC4')) # ror ah; rol ah
        options.append((b'\xD1\xC3', b'\xD1\xCB')) # bx
        options.append((b'\xD0\xC3', b'\xD0\xCB')) # 
        options.append((b'\xD0\xC7', b'\xD0\xCF')) #
        options.append((b'\xD1\xCB', b'\xD1\xC3')) # 
        options.append((b'\xD0\xCB', b'\xD0\xC3')) # 
        options.append((b'\xD0\xCF', b'\xD0\xC7')) #
        options.append((b'\xD1\xC1', b'\xD1\xC9')) # cx
        options.append((b'\xD0\xC1', b'\xD0\xC9')) # 
        options.append((b'\xD0\xC5', b'\xD0\xCD')) #
        options.append((b'\xD1\xC9', b'\xD1\xC1')) # 
        options.append((b'\xD0\xC9', b'\xD0\xC1')) # 
        options.append((b'\xD0\xCD', b'\xD0\xC5')) #
        options.append((b'\xD1\xC2', b'\xD1\xCA')) # dx
        options.append((b'\xD0\xC2', b'\xD0\xCA')) # 
        options.append((b'\xD0\xC6', b'\xD0\xCE')) #
        options.append((b'\xD1\xCA', b'\xD1\xC2')) # 
        options.append((b'\xD0\xCA', b'\xD0\xC2')) # 
        options.append((b'\xD0\xCE', b'\xD0\xC6')) #
        # inc then dec (or vice versa)
        options.append((b'\xFE\xC0', b'\xFE\xC8')) # inc al; dec al
        options.append((b'\xFE\xC4', b'\xFE\xCC')) # inc ah; dec ah
        options.append((b'\xFE\xC8', b'\xFE\xC0')) # dec al; inc al
        options.append((b'\xFE\xCC', b'\xFE\xC4')) # dec ah; inc ah
        options.append((b'\xFE\xC3', b'\xFE\xCB')) # inc bl; dec bl
        options.append((b'\xFE\xC7', b'\xFE\xCF')) # inc bh; dec bh
        options.append((b'\xFE\xCB', b'\xFE\xC3')) # dec bl; inc bl
        options.append((b'\xFE\xCF', b'\xFE\xC7')) # dec bh; inc bh
        options.append((b'\xFE\xC1', b'\xFE\xC9')) # cx
        options.append((b'\xFE\xC5', b'\xFE\xCD')) # 
        options.append((b'\xFE\xC9', b'\xFE\xC1')) # 
        options.append((b'\xFE\xCD', b'\xFE\xC5')) #
        options.append((b'\xFE\xC2', b'\xFE\xCA')) # dx
        options.append((b'\xFE\xC6', b'\xFE\xCE')) # 
        options.append((b'\xFE\xCA', b'\xFE\xC2')) # 
        options.append((b'\xFE\xCE', b'\xFE\xC6')) # 
        # add/sub then sub/add a byte-long immediate value
        #v = chr(random.randint(1, 255))
        v = bytes([random.randint(1, 255)])
        options.append((b'\x04'+v, b'\x2C'+v)) # add al, v; sub al, v
        options.append((b'\x2C'+v, b'\x04'+v)) # sub al, v; add al, v

    if n_bytes>=6:
        #v = chr(random.randint(1, 255))
        v = bytes([random.randint(1, 255)])
        options.append((b'\x80\xC4'+v, b'\x80\xEC'+v)) # add ah, v; sub ah, v
        options.append((b'\x80\xEC'+v, b'\x80\xC4'+v)) # sub ah, v; add ah, v
        options.append((b'\x83\xC0'+v, b'\x83\xE8'+v)) # add eax, v; sub eax, v
        options.append((b'\x83\xE8'+v, b'\x83\xC0'+v)) # sub eax, v; add eax, v
        options.append((b'\x80\xC3'+v, b'\x80\xEB'+v)) # add bl, v; sub bl, v
        options.append((b'\x80\xEB'+v, b'\x80\xC3'+v)) # sub bl, v; add bl, v
        options.append((b'\x80\xC7'+v, b'\x80\xEF'+v)) # add bh, v; sub bh, v
        options.append((b'\x80\xEF'+v, b'\x80\xC7'+v)) # sub bh, v; add bh, v
        options.append((b'\x83\xC3'+v, b'\x83\xEB'+v)) # add ebx, v; sub ebx, v
        options.append((b'\x83\xEB'+v, b'\x83\xC3'+v)) # sub ebx, v; add ebx, v
        options.append((b'\x80\xC1'+v, b'\x80\xE9'+v)) # ecx
        options.append((b'\x80\xE9'+v, b'\x80\xC1'+v)) # 
        options.append((b'\x80\xC5'+v, b'\x80\xED'+v)) # 
        options.append((b'\x80\xED'+v, b'\x80\xC5'+v)) # 
        options.append((b'\x83\xC1'+v, b'\x83\xE9'+v)) # 
        options.append((b'\x83\xE9'+v, b'\x83\xC1'+v)) # 
        options.append((b'\x80\xC2'+v, b'\x80\xEA'+v)) # edx
        options.append((b'\x80\xEA'+v, b'\x80\xC2'+v)) # 
        options.append((b'\x80\xC6'+v, b'\x80\xEE'+v)) # 
        options.append((b'\x80\xEE'+v, b'\x80\xC6'+v)) # 
        options.append((b'\x83\xC2'+v, b'\x83\xEA'+v)) # 
        options.append((b'\x83\xEA'+v, b'\x83\xC2'+v)) # 
        
    # select an option at random
    return random.choice(options)

def reg_altering_nop(n_bytes, protected):
    """
    When the flags register is protected, and reg_x
    is protected, then we can manipulate reg_x without
    any worries.
    """

    assert(protected['ef']), 'Flags register has to be protected here!'
    assert(n_bytes>0), 'n_bytes has to be positive!'
    assert(protected['eax'] or protected['ebx'] or \
           protected['ecx'] or protected['edx']), \
        'hmm... you sure there were protected registers?'

    UF = 8   # to increase/decrease the probability of instructions
             # containing unconstrained bytes
    options = []
    
    # n_bytes >= 1
    if protected['eax']:
        options.append(b'\x40') # inc eax
        options.append(b'\x48') # dec eax
    if protected['ebx']:
        options.append(b'\x43') # inc ebx
        options.append(b'\x4B') # dec ebx
    if protected['ecx']:
        options.append(b'\x41') # inc ecx
        options.append(b'\x49') # dec ecx
    if protected['edx']:
        options.append(b'\x42') # inc edx
        options.append(b'\x4A') # dec edx

    if n_bytes>=2:
        if protected['eax']:
            #v = chr(random.randint(1,255))
            v = bytes([random.randint(1, 255)])
            options.extend([b'\xB0'+v]*UF) # mov al, immediate
            options.extend([b'\xB4'+v]*UF) # mov ah, immediate
            options.append(b'\xF6\xD0') # not al
            options.append(b'\xF6\xD4') # not ah
            options.append(b'\xF7\xD0') # not eax
            options.append(b'\xF6\xD8') # neg al
            options.append(b'\xF6\xDC') # neg ah
            options.append(b'\xF7\xD8') # neg eax
            options.append(b'\xD0\xC0') # rol al
            options.append(b'\xD0\xC4') # rol ah
            options.append(b'\xD1\xC0') # rol eax
            options.append(b'\xD0\xC8') # ror al
            options.append(b'\xD0\xCC') # ror ah
            options.append(b'\xD1\xC8') # ror eax
            options.append(b'\xD0\xF8') # sar al
            options.append(b'\xD0\xE8') # shr al
            options.append(b'\xD0\xE0') # sal al
            options.append(b'\xD0\xFC') # sar ah
            options.append(b'\xD0\xEC') # shr ah
            options.append(b'\xD0\xE4') # sal ah
            options.append(b'\xD1\xF8') # sar eax
            options.append(b'\xD1\xE8') # shr eax
            options.append(b'\xD1\xE0') # sal eax
            options.extend([b'\x04'+v]*UF) # add al, immediate
            options.extend([b'\x14'+v]*UF) # adc al, immediate
            options.extend([b'\x2C'+v]*UF) # sub al, immediate
            options.extend([b'\x1C'+v]*UF) # sbb al, immediate
            options.extend([b'\x0C'+v]*UF) # or al, immediate
            options.extend([b'\x24'+v]*UF) # and al, immediate
            options.extend([b'\x34'+v]*UF) # xor al, immediate
        if protected['ebx']:
            #v = chr(random.randint(1,255))
            v = bytes([random.randint(1, 255)])
            options.extend([b'\xB3'+v]*UF) # mov bl, immediate
            options.extend([b'\xB7'+v]*UF) # mov bh, immediate
            options.append(b'\xF6\xD3') # not bl
            options.append(b'\xF6\xD7') # not bh
            options.append(b'\xF7\xD3') # not ebx
            options.append(b'\xF6\xDB') # neg bl
            options.append(b'\xF6\xDF') # neg bh
            options.append(b'\xF7\xDB') # neg ebx
            options.append(b'\xD0\xC3') # rol bl
            options.append(b'\xD0\xC7') # rol bh
            options.append(b'\xD1\xC3') # rol ebx
            options.append(b'\xD0\xCB') # ror bl
            options.append(b'\xD0\xCF') # ror bh
            options.append(b'\xD1\xCB') # ror ebx
            options.append(b'\xD0\xFB') # sar bl
            options.append(b'\xD0\xEB') # shr bl
            options.append(b'\xD0\xE3') # sal bl
            options.append(b'\xD0\xFF') # sar bh
            options.append(b'\xD0\xEF') # shr bh
            options.append(b'\xD0\xE7') # sal bh
            options.append(b'\xD1\xFB') # sar ebx
            options.append(b'\xD1\xEB') # shr ebx
            options.append(b'\xD1\xE3') # sal ebx
        if protected['ecx']:
            #v = chr(random.randint(1,255))
            v = bytes([random.randint(1, 255)])
            options.extend([b'\xB1'+v]*UF) # mov cl, immediate
            options.extend([b'\xB5'+v]*UF) # mov ch, immediate
            options.append(b'\xF6\xD1') # not cl
            options.append(b'\xF6\xD5') # not ch
            options.append(b'\xF7\xD1') # not ecx
            options.append(b'\xF6\xD9') # neg cl
            options.append(b'\xF6\xDD') # neg ch
            options.append(b'\xF7\xD9') # neg ecx
            options.append(b'\xD0\xC1') # rol cl
            options.append(b'\xD0\xC5') # rol ch
            options.append(b'\xD1\xC1') # rol ecx
            options.append(b'\xD0\xC9') # ror cl
            options.append(b'\xD0\xCD') # ror ch
            options.append(b'\xD1\xC9') # ror ecx
            options.append(b'\xD0\xF9') # sar cl
            options.append(b'\xD0\xE9') # shr cl
            options.append(b'\xD0\xE1') # sal cl
            options.append(b'\xD0\xFD') # sar ch
            options.append(b'\xD0\xED') # shr ch
            options.append(b'\xD0\xE5') # sal ch
            options.append(b'\xD1\xF9') # sar ecx
            options.append(b'\xD1\xE9') # shr ecx
            options.append(b'\xD1\xE1') # sal ecx
        if protected['edx']:
            #v = chr(random.randint(1,255))
            v = bytes([random.randint(1, 255)])
            options.extend([b'\xB2'+v]*UF) # mov dl, immediate
            options.extend([b'\xB6'+v]*UF) # mov dh, immediate
            options.append(b'\xF6\xD2') # not dl
            options.append(b'\xF6\xD6') # not dh
            options.append(b'\xF7\xD2') # not edx
            options.append(b'\xF6\xDA') # neg dl
            options.append(b'\xF6\xDE') # neg dh
            options.append(b'\xF7\xDA') # neg edx
            options.append(b'\xD0\xC2') # rol dl
            options.append(b'\xD0\xC6') # rol dh
            options.append(b'\xD1\xC2') # rol edx
            options.append(b'\xD0\xCA') # ror dl
            options.append(b'\xD0\xCE') # ror dh
            options.append(b'\xD1\xCA') # ror edx
            options.append(b'\xD0\xFA') # sar dl
            options.append(b'\xD0\xEA') # shr dl
            options.append(b'\xD0\xE2') # sal dl
            options.append(b'\xD0\xFE') # sar dh
            options.append(b'\xD0\xEE') # shr dh
            options.append(b'\xD0\xE6') # sal dh
            options.append(b'\xD1\xFA') # sar edx
            options.append(b'\xD1\xEA') # shr edx
            options.append(b'\xD1\xE2') # sal edx

    if n_bytes>=3:
        if protected['eax']:
            #v = chr(random.randint(1,255))
            v = bytes([random.randint(1, 255)])
            options.extend([b'\x80\xC4'+v]*UF) # add ah, v
            options.extend([b'\x80\xD4'+v]*UF) # adc ah, v
            options.extend([b'\x80\xEC'+v]*UF) # sub ah, v
            options.extend([b'\x80\xDC'+v]*UF) # sbb ah, v
            options.extend([b'\x80\xCC'+v]*UF) # or ah, v
            options.extend([b'\x80\xE4'+v]*UF) # and ah, v
            options.extend([b'\x80\xF4'+v]*UF) # xor ah, v
        if protected['ebx']:
            #v = chr(random.randint(1,255))
            v = bytes([random.randint(1, 255)])
            options.extend([b'\x80\xC3'+v]*UF) # add bl, v
            options.extend([b'\x80\xD3'+v]*UF) # adc bl, v
            options.extend([b'\x80\xEB'+v]*UF) # sub bl, v
            options.extend([b'\x80\xDB'+v]*UF) # sbb bl, v
            options.extend([b'\x80\xCB'+v]*UF) # or bl, v
            options.extend([b'\x80\xE3'+v]*UF) # and bl, v
            options.extend([b'\x80\xF3'+v]*UF) # xor bl, v
            options.extend([b'\x80\xC7'+v]*UF) # add bh, v
            options.extend([b'\x80\xD7'+v]*UF) # adc bh, v
            options.extend([b'\x80\xEF'+v]*UF) # sub bh, v
            options.extend([b'\x80\xDF'+v]*UF) # sbb bh, v
            options.extend([b'\x80\xCF'+v]*UF) # or bh, v
            options.extend([b'\x80\xE7'+v]*UF) # and bh, v
            options.extend([b'\x80\xF7'+v]*UF) # xor bh, v
        if protected['ecx']:
            #v = chr(random.randint(1,255))
            v = bytes([random.randint(1, 255)])
            options.extend([b'\x80\xC1'+v]*UF) # add cl, v
            options.extend([b'\x80\xD1'+v]*UF) # adc cl, v
            options.extend([b'\x80\xE9'+v]*UF) # sub cl, v
            options.extend([b'\x80\xD9'+v]*UF) # sbb cl, v
            options.extend([b'\x80\xC9'+v]*UF) # or cl, v
            options.extend([b'\x80\xE1'+v]*UF) # and cl, v
            options.extend([b'\x80\xF1'+v]*UF) # xor cl, v
            options.extend([b'\x80\xC5'+v]*UF) # add ch, v
            options.extend([b'\x80\xD5'+v]*UF) # adc ch, v
            options.extend([b'\x80\xED'+v]*UF) # sub ch, v
            options.extend([b'\x80\xDD'+v]*UF) # sbb ch, v
            options.extend([b'\x80\xCD'+v]*UF) # or ch, v
            options.extend([b'\x80\xE5'+v]*UF) # and ch, v
            options.extend([b'\x80\xF5'+v]*UF) # xor ch, v
        if protected['edx']:
            #v = chr(random.randint(1,255))
            v = bytes([random.randint(1, 255)])
            options.extend([b'\x80\xC2'+v]*UF) # add dl, v
            options.extend([b'\x80\xD2'+v]*UF) # adc dl, v
            options.extend([b'\x80\xEA'+v]*UF) # sub dl, v
            options.extend([b'\x80\xDA'+v]*UF) # sbb dl, v
            options.extend([b'\x80\xCA'+v]*UF) # or dl, v
            options.extend([b'\x80\xE2'+v]*UF) # and dl, v
            options.extend([b'\x80\xF2'+v]*UF) # xor dl, v
            options.extend([b'\x80\xC6'+v]*UF) # add dh, v
            options.extend([b'\x80\xD6'+v]*UF) # adc dh, v
            options.extend([b'\x80\xEE'+v]*UF) # sub dh, v
            options.extend([b'\x80\xDE'+v]*UF) # sbb dh, v
            options.extend([b'\x80\xCE'+v]*UF) # or dh, v
            options.extend([b'\x80\xE6'+v]*UF) # and dh, v
            options.extend([b'\x80\xF6'+v]*UF) # xor dh, v

    if n_bytes>=5:
        if protected['eax']:
            v = struct.pack('<I', random.randint(0,2**31-1))
            options.extend([b'\x05'+bytes(v)]*UF*UF) # add eax, v
            options.extend([b'\x15'+bytes(v)]*UF*UF) # adc eax, v
            options.extend([b'\x2D'+bytes(v)]*UF*UF) # sub eax, v
            options.extend([b'\x1D'+bytes(v)]*UF*UF) # sbb eax, v
            options.extend([b'\x0D'+bytes(v)]*UF*UF) # or eax, v
            options.extend([b'\x25'+bytes(v)]*UF*UF) # and eax, v
            options.extend([b'\x35'+bytes(v)]*UF*UF) # xor eax, v
            
    if n_bytes>=6:
        if protected['ebx']:
            v = struct.pack('<I', random.randint(0,2**31-1))
            options.extend([b'\x81\xc3'+bytes(v)]*UF*UF) # add ebx, v
            options.extend([b'\x81\xd3'+bytes(v)]*UF*UF) # adc ebx, v
            options.extend([b'\x81\xeb'+bytes(v)]*UF*UF) # sub ebx, v
            options.extend([b'\x81\xdb'+bytes(v)]*UF*UF) # sbb ebx, v
            options.extend([b'\x81\xcb'+bytes(v)]*UF*UF) # or ebx, v
            options.extend([b'\x81\xe3'+bytes(v)]*UF*UF) # and ebx, v
            options.extend([b'\x81\xf3'+bytes(v)]*UF*UF) # xor ebx, v
        if protected['ecx']:
            v = struct.pack('<I', random.randint(0,2**31-1))
            options.extend([b'\x81\xc1'+bytes(v)]*UF*UF) # add ecx, v
            options.extend([b'\x81\xd1'+bytes(v)]*UF*UF) # adc ecx, v
            options.extend([b'\x81\xe9'+bytes(v)]*UF*UF) # sub ecx, v
            options.extend([b'\x81\xd9'+bytes(v)]*UF*UF) # sbb ecx, v
            options.extend([b'\x81\xc9'+bytes(v)]*UF*UF) # or ecx, v
            options.extend([b'\x81\xe1'+bytes(v)]*UF*UF) # and ecx, v
            options.extend([b'\x81\xf1'+bytes(v)]*UF*UF) # xor ecx, v
        if protected['edx']:
            v = struct.pack('<I', random.randint(0,2**31-1))
            options.extend([b'\x81\xc2'+bytes(v)]*UF*UF) # add edx, v
            options.extend([b'\x81\xd2'+bytes(v)]*UF*UF) # adc edx, v
            options.extend([b'\x81\xea'+bytes(v)]*UF*UF) # sub edx, v
            options.extend([b'\x81\xda'+bytes(v)]*UF*UF) # sbb edx, v
            options.extend([b'\x81\xca'+bytes(v)]*UF*UF) # or edx, v
            options.extend([b'\x81\xe2'+bytes(v)]*UF*UF) # and edx, v
            options.extend([b'\x81\xf2'+bytes(v)]*UF*UF) # xor edx, v
            
    # select an option at random
    choice = random.choice(options)

    # set unconstrained idxs (the ones occupied by v)
    uidxs = []
    if len(choice)==2:
        if choice[0] in [b'\xB0', b'\xB4', b'\x04', b'\x14', b'\x2C', b'\x1C',
                         b'\x0C', b'\x24', b'\x34', b'\xB3', b'\xB7', b'\xB1',
                         b'\xB5', b'\xB2', b'\xB6']:
            uidxs = [1]
    if len(choice)==3:
        if choice[:2] in [b'\x80\xC4', b'\x80\xD4', b'\x80\xEC', b'\x80\xDC', b'\x80\xCC',
                          b'\x80\xE4', b'\x80\xF4', b'\x80\xC3', b'\x80\xD3', b'\x80\xEB',
                          b'\x80\xDB', b'\x80\xCB', b'\x80\xE3', b'\x80\xF3', b'\x80\xC7',
                          b'\x80\xD7', b'\x80\xEF', b'\x80\xDF', b'\x80\xCF', b'\x80\xE7',
                          b'\x80\xF7', b'\x80\xC1', b'\x80\xD1', b'\x80\xE9', b'\x80\xD9',
                          b'\x80\xC9', b'\x80\xE1', b'\x80\xF1', b'\x80\xC5', b'\x80\xD5',
                          b'\x80\xED', b'\x80\xDD', b'\x80\xCD', b'\x80\xE5', b'\x80\xF5',
                          b'\x80\xC2', b'\x80\xD2', b'\x80\xEA', b'\x80\xDA', b'\x80\xCA',
                          b'\x80\xE2', b'\x80\xF2', b'\x80\xC6', b'\x80\xD6', b'\x80\xEE',
                          b'\x80\xDE', b'\x80\xCE', b'\x80\xE6', b'\x80\xF6']:
            uidxs = [2]
    if len(choice)==5:
        if choice[0] in [b'\x05', b'\x15', b'\x2D', b'\x1D', \
                         b'\x0D', b'\x25', b'\x35']:
            uidxs = [1,2,3,4]
    if len(choice)==6:
        if choice[0]==b'\x81':
            uidxs = [2,3,4,5]
        
    # done
    return choice, uidxs
    
def get_semantic_nop(n_bytes, protected=None, start_idx=None, \
                     get_unconstrained_idxs=False):
    """
    get instructions that do not affect execution
    (i.e., memory, register, and EF values are the
    same before and after execution) whose byte
    representation fills n_bytes.
    """

    # corners
    if n_bytes==0:
        if get_unconstrained_idxs:
            return '', []
        return ''
    if n_bytes<0:
        raise ValueError('n_bytes has to be >= 0')
    
    # Non of the registers have been "protected" yet
    # (by storing them to the stack)
    if protected==None:
        protected = {'eax': False, \
                     'ebx': False, \
                     'ecx': False, \
                     'edx': False, \
                     'ef': False}

    # init start_idx
    if start_idx is None:
        start_idx = 0
        
    # set viable semantic nops (depending on n_bytes
    # and which registers are currently protected)
    possible_nops = ['atomic_nop']
    if n_bytes>=2:
        possible_nops.extend(['preserv_eax', \
                              'preserv_ebx', \
                              'preserv_ecx', \
                              'preserv_edx'])
    if (protected['eax'] and n_bytes>=2) or n_bytes>=4:
        times = 8
        if protected['ef']:
            times = 1
        possible_nops.extend(['preserv_ef']*times)
    if n_bytes>=4:
        possible_nops.extend(['split', \
                              'combo_nop']*2)
    if protected['ef']:
        possible_nops.extend(['ef_altering']*4)
        if protected['eax']:
            possible_nops.extend(['reg_altering']*16)
        if protected['ebx']:
            possible_nops.extend(['reg_altering']*16)
        if protected['ecx']:
            possible_nops.extend(['reg_altering']*16)
        if protected['edx']:
            possible_nops.extend(['reg_altering']*16)

    # select nop type, and draw a random semantic nop
    nop_type = random.choice(possible_nops)
    unconstrained_idxs = []
    if nop_type=='atomic_nop':
        n_atomic = random.randint(1, min(n_bytes, 3))
        pre = atomic_nop(n_atomic)
        suf, unconstrained_idxs = get_semantic_nop(n_bytes-n_atomic, protected, \
                                                   start_idx+len(pre), True)
        res = pre + suf
    elif nop_type=='preserv_eax':
        # push eax; semantic nop; pop eax
        tmp = protected['eax']
        protected['eax'] = True
        mid, unconstrained_idxs = get_semantic_nop(n_bytes-2, protected, \
                                                   start_idx+1, True)
        res = b'\x50' + mid + b'\x58'
        protected['eax'] = tmp
    elif nop_type=='preserv_ebx':
        # push ebx; semantic nop; pop ebx
        tmp = protected['ebx']
        protected['ebx'] = True
        mid, unconstrained_idxs = get_semantic_nop(n_bytes-2, protected, \
                                                   start_idx+1, True)
        res = b'\x53' + mid + b'\x5b'
        protected['ebx'] = tmp
    elif nop_type=='preserv_ecx':
        # push ecx; semantic nop; pop ecx
        tmp = protected['ecx']
        protected['ecx'] = True
        mid, unconstrained_idxs = get_semantic_nop(n_bytes-2, protected, \
                                                   start_idx+1, True)
        res = b'\x51' + mid + b'\x59'
        protected['ecx'] = tmp
    elif nop_type=='preserv_edx':
        # push edx; semantic nop; pop edx
        tmp = protected['edx']
        protected['edx'] = True
        mid, unconstrained_idxs = get_semantic_nop(n_bytes-2, protected, \
                                                   start_idx+1, True)
        res = b'\x52' + mid + b'\x5a'
        protected['edx'] = tmp
    elif nop_type=='preserv_ef':
        if not protected['eax']:
            pre = b'\x50\x9f'
            suf = b'\x9e\x58'
        else:
            pre = b'\x9f'
            suf = b'\x9e'
        tmp1 = protected['eax']
        tmp2 = protected['ef']
        protected['eax'] = False
        protected['ef'] = True
        n_bytes = n_bytes-len(pre)-len(suf)
        mid, unconstrained_idxs = get_semantic_nop(n_bytes, protected, \
                                                   start_idx+len(pre), True)
        res = pre + mid + suf
        protected['eax'] = tmp1
        protected['ef'] = tmp2
    elif nop_type=='split':
        n_bytes1 = random.randint(1, n_bytes-1)
        n_bytes2 = n_bytes - n_bytes1
        pre, uidxs1 = get_semantic_nop(n_bytes1, protected, start_idx, True)
        suf, uidxs2 = get_semantic_nop(n_bytes2, protected, start_idx+n_bytes1, True)
        res = pre+suf
        unconstrained_idxs = uidxs1+uidxs2
    elif nop_type=='combo_nop':
        pre, suf = combo_nop()
        n_bytes = n_bytes-len(pre)-len(suf)
        mid, unconstrained_idxs = get_semantic_nop(n_bytes, protected, \
                                                   start_idx+len(pre), True)
        res = pre + mid + suf
    elif nop_type=='ef_altering':
        pre, suf = ef_altering_nop(n_bytes)
        n_bytes = n_bytes-len(pre)-len(suf)
        mid, unconstrained_idxs = get_semantic_nop(n_bytes, protected, \
                                                   start_idx+len(pre), True)
        res = pre + mid + suf
    elif nop_type=='reg_altering':
        pre, uidxs1 = reg_altering_nop(n_bytes, protected)
        uidxs1 = [start_idx+idx for idx in uidxs1]
        suf, uidxs2 = get_semantic_nop(n_bytes-len(pre), protected, \
                                       start_idx+len(pre), True)
        res = pre + suf
        unconstrained_idxs = uidxs1+uidxs2
    else:
        raise ValueError('Unknown nop type: %s'%nop_type)
    
    # done
    if get_unconstrained_idxs:
        return res, unconstrained_idxs
    return res
    
def can_semnops(f):
    """
    checks if function has any semnops that 
    can be replaced
    """
    if hasattr(f, 'displaced_bytes'):
        return True
    return False

def do_semnops(f):
    """
    Replace nops/semantic nops in f with randomly
    generated ones
    """
    
    diffs = []
    changed_bytes = set()
    if hasattr(f, 'displaced_bytes'):
        for i in range(len(f.displaced_bytes)-1):
            addresses = f.displaced_bytes[i]
            n_bytes = addresses[1]-addresses[0]-5+1
            semnop_bytes = get_semantic_nop(n_bytes)
            for j in range(n_bytes):
                ea = addresses[0]+5+j
                diffs.append((ea, None, semnop_bytes[j])) # note: set orig to "None" to save time retrieving the current value
                changed_bytes.add(ea)

    if hasattr(f, 'ropf_semnops'):
        for semnop_bin in f.ropf_semnops:
            new_semnop_bytes = get_semantic_nop(len(semnop_bin))
            new_semnop_bin = [b for b in new_semnop_bytes]
            for i in range(len(semnop_bin)):
                semnop_bin[i] = new_semnop_bin[i]

    return diffs, changed_bytes

if __name__=='__main__':
    # import pydasm
    # lst = [
    #     b'\x66\x21\xc0',   # and eax, eax (?)
    #     b'\x66\x09\xc0',   # or eax, eax (?)
    #     b'\x66\x85\xc0',   # test eax, eax (?)
    #     b'\xd1\xc0\xd1\xc8', # rol eax, 1; ror eax 1 (?)
    #     b'\x50\x9f\x9e\x58', # push eax; lahf; sahf; pop eax
    #                         # (can do a bunch of things in the middle!)
    #     b'\x50\x58',        # push eax; pop eax
    #     b'\x0f\xc8\x0f\xc8',   # bswap eax; bswap eax
    # ]
    # for bytes in lst:
    #     inst = pydasm.get_instruction(bytes, pydasm.MODE_32)
    #     bytes_str = ''.join(['%02x'%ord(b) for b in bytes])
    #     disas = pydasm.get_instruction_string(inst, pydasm.FORMAT_INTEL, 0)
    #     print('%s -> %s'%(bytes_str, disas))
    nop_bytes, uidxs = get_semantic_nop(40, get_unconstrained_idxs=True)
    print(('nop bytes: %s'%(' '.join(['%02x'%ord(b) for b in nop_bytes]),)))
    print(('Unconstrained idxs: %s'%uidxs))
    
