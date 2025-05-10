# a26095cf5fff9a7ec04c3fd3fb60372f38f3dc300addf4983e0ce4f7490ef7b2


import re

def extract_ascii_strings(file_path, min_length=4):
    with open(file_path, 'rb') as f:
        data = f.read()
    pattern = rb'[ -~]{%d,}' % min_length 
    return [s.decode('ascii') for s in re.findall(pattern, data)]

# Usage
mw_string = extract_ascii_strings('a26095cf5fff9a7ec04c3fd3fb60372f38f3dc300addf4983e0ce4f7490ef7b2.exe')
for i in range(len(mw_string)):
    if mw_string[i] == "string too long":
        key = mw_string[i+3]
        break

import base64
import binascii

def decode_base64(s):
    return base64.b64decode(s)


def is_base64(s):
    try:
        s = s.strip()
        if len(s) % 4 != 0:
            return False
        decoded = base64.b64decode(s, validate=True)
        return base64.b64encode(decoded).decode() == s
    except (binascii.Error, UnicodeDecodeError):
        return False


def rc4_crypt(data, key):
    S = list(range(256))
    j = 0

    # Key Scheduling Algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(byte ^ K)

    return bytes(out)

#print(rc4_crypt(decode_base64("kqKYpocdGskw5F3N"),key.encode()))

decrypted_strings = []

start_point = False
end_point = False
for i in range(len(mw_string)):
    if mw_string[i] == "string too long":
        start_point = True
    if start_point:
        if is_base64(mw_string[i]):
            dec = rc4_crypt(decode_base64(mw_string[i]),key.encode())
            try:
                decrypted_strings.append(dec.decode())
            except:
                pass
    
    if "%s" in mw_string[i]:
        break


import re

def find_ip_address(lst):
    ip_pattern = re.compile(
        r'^('
        r'(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'     
        r'\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'   
        r'\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'   
        r'\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'   
        r')$'
    )

    return [(i, item) for i, item in enumerate(lst) if ip_pattern.match(item)]


C2 = find_ip_address(decrypted_strings)[0][1]
idx = find_ip_address(decrypted_strings)[0][0]

print("===== C2 config ======")

print(f"    key : {key}")
print(f"    C2 : {C2}{decrypted_strings[idx+1]}")

print("==== Decrypted Strings ======")
for s in decrypted_strings:
    print(s)
