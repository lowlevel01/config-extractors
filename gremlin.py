# 07f8ce4b24858737bfa4c0b51f37f46066f2ca8a
# Extracts the C2 

import re

def xor(data, key):
    return bytes(b ^ key for b in data)


import dnfile

pee = dnfile.dnPE(".\\Gremlin.exe.bin")

for r in pee.net.resources:
    if r.name == "resource":
        resource = r.data


url_pattern = re.compile(
        r'\bhttps?://'
        r'(?:'
            r'(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,6}'
            r'|'
            r'\d{1,3}(?:\.\d{1,3}){3}'
            r'|\[[A-Fa-f0-9:]+\]'
        r')'
        r'(?::\d{1,5})?'
        r'(?:/[A-Za-z0-9\-._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]*)?'
        r'\b',
        re.IGNORECASE | re.ASCII
    )

for key in range(1,256):
    result = xor(resource, key).decode('utf-8', errors="ignore")
    
    URLs = url_pattern.findall(result)

    if URLs:
        print(*URLs)
