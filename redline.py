from dotnetfile import DotNetPE
import base64
import sys



dotnet_file_path = sys.argv[1]

dotnet_file = DotNetPE(dotnet_file_path)



def get_stream_data(file, stream):
        addr = file.dotnet_stream_lookup[stream].address
        size = file.dotnet_stream_lookup[stream].size
        return file.get_data(addr, size)
    
us_stream = get_stream_data(dotnet_file, "#US")

stream = ""
for i in range(len(us_stream)):
    if i % 2 :
        stream += chr(us_stream[i])


def xor_decrypt(data, key):
    return bytes([data[i] ^ ord(key[i % len(key)]) for i in range(len(data))])
def StringDecrypt(encoded_str, key):
    decoded_data = base64.b64decode(encoded_str)
    decrypted_data = xor_decrypt(decoded_data, key)
    final_result = base64.b64decode(decrypted_data)
    return final_result

stream = stream.replace("\x00"," ").split(" ")

encrypted_c2 = stream[-4]
key = stream[-2]

c2 = StringDecrypt(encrypted_c2, key)

print("Here is the C2 Server:", c2.decode())


