# works on the reflectively loaded dll, otherwise implement the png extraction and then use binwlalk or something
# msbuild.exe : 7290353a3bc2b18e9ea574d3294b09e28edaa6b038285bb101cf09760f187dcd

import pefile
import struct
import re

def rc4_crypt(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(byte ^ K)
    return bytes(out)

def decrypt_config(path):
    pe = pefile.PE(path)
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00")
        if name == ".rdata":
            raw = section.get_data()

            length = struct.unpack("<I", raw[:4])[0]
            encrypted = raw[4:4+length]
            key = list(raw[4+length:4+length+16])

            decrypted = rc4_crypt(encrypted, key)
            return decrypted


decrypted = decrypt_config("dll.bin")


print("config dump no enery to parse it :( ")
strings = re.findall(rb"[\x20-\x7E]{4,}", decrypted)
for s in strings:
    print(s.decode(errors='ignore'))
