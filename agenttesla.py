# 94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e

import clr
import os
import sys

sys.path.append(os.getcwd())

clr.AddReference("dnlib")

from dnlib.DotNet import ModuleDefMD
from dnlib.DotNet.Emit import OpCodes

file = "94491241e60bd744ff41c9f33cd39b02ee968cfce120720be9e8a849b8e39c0e"

module = ModuleDefMD.Load(file)

#sequence of opcodes to locate config
opcodes = [
    "ldstr", "stsfld", "ldstr", "stsfld", "ldstr", "stsfld", "ldstr", "stsfld","ldstr", "call",
      "stsfld", "ldstr", "stsfld", "ldstr", "call", "stsfld",
]

print("\n\nAgentTesla Config:")
print("=====================\n\n")

for type_def in module.GetTypes():
    for method in type_def.Methods:
        if method.HasBody:
            #print(f"Method: {method.FullName}")
            count = 0
            instructions = method.Body.Instructions
            for instr in instructions:
                if instr.OpCode.Name == opcodes[count]:
                    count += 1
                if count == 16:
                    for instr in instructions:
                        if instr.OpCode.Name == "ldstr":
                            string = instr.Operand
                        if instr.OpCode.Name == "stsfld":
                            variable = instr.Operand
                            variable = str(variable).split("::")[-1]
                            print(variable+" : "+string+"\n")
                    break
