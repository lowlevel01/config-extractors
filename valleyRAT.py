# 31cb03542a162f39f7bf1854bd38089cc7cab44f6114b472eeaa9b424bc99c34
import pefile
from capstone import *

file = "31cb03542a162f39f7bf1854bd38089cc7cab44f6114b472eeaa9b424bc99c34"

pe = pefile.PE(file)

pattern = [
    "push",
    "mov",
    "sub",
    "cmp",
    "jne",
    "push",
    "push",
]

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False
md.skipdata = True

image_base = pe.OPTIONAL_HEADER.ImageBase


text_section = None
for s in pe.sections:
    if s.Name.rstrip(b"\x00") == b".text":
        text_section = s
        break

if text_section is None:
    raise RuntimeError(".text section not found")

code = text_section.get_data()
start_va = image_base + text_section.VirtualAddress

insns = list(md.disasm(code, start_va))

for i in range(len(insns) - len(pattern) + 1):
    window = insns[i:i + len(pattern)]
    if [ins.mnemonic for ins in window] == pattern:
        addr = int(window[-1].op_str, 16)
        rva = addr - pe.OPTIONAL_HEADER.ImageBase
        file_offset = pe.get_offset_from_rva(rva)
        data = pe.__data__[file_offset:file_offset + 1000].decode("utf-16")[::-1]
        print(data)

c2 = {}
other = {}

for item in data.strip("|").split("|"):
    if ":" not in item:
        continue
    k, v = item.split(":", 1)

    if k[-1].isdigit():
        idx = int(k[-1])
        key = k[:-1]
        c2.setdefault(idx, {})[key] = v
    else:
        other[k] = v

c2_list = []
for i in sorted(c2):
    c2_list.append({
        "ip": c2[i].get("p"),
        "port": int(c2[i].get("o", 0)),
        "type": c2[i].get("t"),
    })

print(c2_list)
print(other)

