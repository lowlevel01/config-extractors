# Reference: https://n1ght-w0lf.github.io/tutorials/dotnet-string-decryptor/

# Works for all samples on Vx-Underground

import clr
clr.AddReference("System")
from System import Int32
from System.Reflection import Assembly, BindingFlags, MethodInfo

clr.AddReference("C:\\Users\\Admin\\Desktop\\Samples\\agniane\\dnlib.dll")  
import dnlib
from dnlib.DotNet import ModuleDef, ModuleDefMD
from dnlib.DotNet.Emit import OpCodes
from dnlib.DotNet.Writer import ModuleWriterOptions

import re

url_pattern = re.compile(
    r'^(https?://)'  
    r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}'  
    r'(:\d{1,5})?'  
    r'(/[a-zA-Z0-9@:%._\\+~#?&/=]*)?$'  
)

ip_port_pattern = re.compile(
    r'^('
    r'((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}'
    r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
    r')(:\d{1,5})?$'
)

import base64
    

file_module = ModuleDefMD.Load("C:\\Users\\Admin\\Desktop\\Samples\\agniane\\abce9c19df38717374223d0c45ce2d199f77371e18f9259b9b145fe8d5a978af")
file_assembly = Assembly.LoadFile("C:\\Users\\Admin\\Desktop\\Samples\\agniane\\abce9c19df38717374223d0c45ce2d199f77371e18f9259b9b145fe8d5a978af")

DECRYPTION_METHOD_SIGNATURES = [
    {
        "Parameters": ["System.Int32"],
        "ReturnType": "System.String"
    },
    {
        "Parameters": ["System.Int32"],
        "ReturnType": "System.Object"
    },
]


def GetOperandValue(insn, paramType):
    if "Int32" in paramType:
        if insn.IsLdcI4():
            return Int32(insn.GetLdcI4Value())
    elif "String" in paramType:
        if insn.OpCode == OpCodes.Ldstr:
            return insn.Operand
    else:
        return None

suspected_methods = dict()


eFlags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic

for module_type in file_assembly.GetTypes():
    for method in module_type.GetMethods(eFlags):
        
        for sig in DECRYPTION_METHOD_SIGNATURES:
            
            try:
                parameters = method.GetParameters()
                if ((len(parameters) == len(sig["Parameters"])) and
                    (method.ReturnType.FullName == sig["ReturnType"])):
                
                    
                    param_types_match = True
                    for i in range(len(parameters)):
                        if parameters[i].ParameterType.FullName != sig["Parameters"][i]:
                            param_types_match = False
                            break

                    if param_types_match:
                        
                        method_name = f"{method.DeclaringType.FullName}::{method.Name}"
                        suspected_methods[method_name] = (sig, method)
            except:
                pass


for module_type in file_module.Types:
    if not module_type.HasMethods:
        continue

    for method in module_type.Methods:
        if not method.HasBody:
            continue

        
        for insnIdx, insn in enumerate(method.Body.Instructions):
            
            if insn.OpCode == OpCodes.Call:
                for s_method_name, (s_method_sig, s_method_info) in suspected_methods.items():
                    
                    if str(s_method_name) in str(insn.Operand):
                        
                                params = []
                                for i in range(len(s_method_sig["Parameters"])):
                                    operand = GetOperandValue(
                                        method.Body.Instructions[insnIdx - i - 1],
                                        s_method_sig["Parameters"][-i - 1])
                                    if operand is not None:
                                        params.append(operand)

                                
                                if len(params) == len(s_method_sig["Parameters"]):
                                    
                                    try:
                                        result = str(s_method_info.Invoke(None, params[::-1]))
                                        if url_pattern.match(result) or ip_port_pattern.match(result):
                                                print("FOUND: ", result)
                                        try:

                                            c2 = base64.b64decode(result).decode()
                                            if url_pattern.match(c2) or ip_port_pattern.match(c2):
                                                print("FOUND: ", c2)
                                        except:
                                            continue
                                    except Exception as e:
                                        continue

                                    
                                    for i in range(len(s_method_sig["Parameters"])):
                                        method.Body.Instructions[insnIdx - i - 1].OpCode = OpCodes.Nop

                                    
                                    method.Body.Instructions[insnIdx].OpCode = OpCodes.Ldstr
                                    method.Body.Instructions[insnIdx].Operand = result



from dotnetfile import DotNetPE
dotnet_file = DotNetPE(file_assembly)
def is_base64(s):

    if not base64_pattern.match(s):
        return False
    try:
        decoded_bytes = base64.b64decode(s, validate=True)
        return base64.b64encode(decoded_bytes).decode('ascii').rstrip('=') == s.rstrip('=')
    except Exception:
        return False

def get_stream_data(file, stream):
        addr = file.dotnet_stream_lookup[stream].address
        size = file.dotnet_stream_lookup[stream].size
        return file.get_data(addr, size)
    
us_stream = get_stream_data(dotnet_file, "#US")

stream = ""
for i in range(len(us_stream)):
    if i % 2 :
        stream += chr(us_stream[i])


us_stream_strings = dotnet_file.get_user_stream_strings()

url_pattern = re.compile(
    r'^(https?://)'  
    r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}'  
    r'(:\d{1,5})?'  
    r'(/[a-zA-Z0-9@:%._\\+~#?&/=]*)?$'  
)

ip_port_pattern = re.compile(
    r'^('
    r'((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}'
    r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
    r')(:\d{1,5})?$'
)

base64_pattern = re.compile(
    r'^(?:[A-Za-z0-9+/]{4})*'        
    r'(?:[A-Za-z0-9+/]{2}=='         
    r'|[A-Za-z0-9+/]{3}=)?$'         
)

domains = []
ip_addresses = []
base64_strings = []

for item in us_stream_strings:
    if url_pattern.match(item):
        domains.append(item)
    elif ip_port_pattern.match(item):
        ip_addresses.append(item)
    elif is_base64(item):
        try:
            decoded_string = base64.b64decode(item, validate=True).decode("utf-8")
            if url_pattern.match(decoded_string):
                print("Found C2: "+base64.b64decode(item, validate=True).decode())
        except:
            continue

print("\n")
print("Domains:", domains)
print("IP Addresses:", ip_addresses)
