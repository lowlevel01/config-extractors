from Crypto.Cipher import ChaCha20
from binascii import unhexlify

#LummaC2 uses chacha20 to encrypt the config

def chacha20_decrypt_hex(key_hex, nonce_hex, ciphertext_hex):
    key = unhexlify(key_hex)
    nonce = unhexlify(nonce_hex)
    ciphertext = unhexlify(ciphertext_hex)

    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


from capstone import *
from capstone.x86 import *
# Several way to identify the config
# In this POC I'll use the sequence of opcodes signature

sig = ['mov','lea','mov','mov','mov','mov','mov','mov','mov','mov','mov','mov','mov','mov','mov','mov','mov','mov','mov','mov','mov']

def find_instruction_pattern(binary_data, start_address, pattern):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True 
    md.skipdata = True
    instructions = list(md.disasm(binary_data, start_address))
    pattern_length = len(pattern)
    for i in range(len(instructions) - pattern_length + 1):
        #print(f"0x{instructions[i].address:X} : {instructions[i].mnemonic}")
        window = instructions[i:i + pattern_length]
        mnemonics = list([instr.mnemonic for instr in window])
        #print(mnemonics)
        if mnemonics == pattern:
            last_instr = window[-1]
            target_address = last_instr.address - 0x87
            for instr in instructions:
                if instr.address == target_address:
                    if len(instr.operands) >= 2:
                        op = instr.operands[1]
                        if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                            return op.mem.disp
            return None


import pefile

def extract_text_section(pe):

    # Iterate through the sections to find the .text section
    for section in pe.sections:
        if section.Name.startswith(b'.text'):
            return section.get_data(), section.VirtualAddress
    return None, None

def va_to_file_offset(pe, va):
    for section in pe.sections:
        if section.VirtualAddress <= va < (section.VirtualAddress + section.Misc_VirtualSize):
            offset = va - section.VirtualAddress + section.PointerToRawData
            return offset
    return None


def read_global_bytes(pe, file_path, va, length):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    offset = va_to_file_offset(pe, rva)

    if offset is None:
        print(f"[!] Could not resolve RVA 0x{rva:X} (VA 0x{va:X}) to file offset.")
        return None

    with open(file_path, "rb") as f:
        f.seek(offset)
        data = f.read(length)
        return data.hex()


def debug_pe_sections(pe):
    print("=== PE Sections ===")
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + section.Misc_VirtualSize
        print(f"{section.Name.decode().rstrip(chr(0))}: VA 0x{start:X} - 0x{end:X}")
    print("====================")

if __name__ == "__main__":
    pe_file_path = ".\\lumma.exe"
    pe = pefile.PE(pe_file_path)

    text_section_data, text_section_va = extract_text_section(pe)

    if text_section_data:
        va = find_instruction_pattern(text_section_data, text_section_va, sig)
        print(hex(va))
        key = read_global_bytes(pe, pe_file_path, va, 32)
        nonce = read_global_bytes(pe, pe_file_path, va+32, 8)
        
        
        #Let's start decrypting C2's

        enc_c2 = read_global_bytes(pe, pe_file_path, va+32+8, 128*16)
        
        dec_blob = chacha20_decrypt_hex(key, nonce, enc_c2)

        for i in range(32):
            try:
                chunk = dec_blob[i*128 : (i+1)*128]
                nul_terminated = chunk[:chunk.index(b'\x00')]
                print(nul_terminated.decode())
            except:
                break
