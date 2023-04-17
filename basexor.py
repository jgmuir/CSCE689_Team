# Brandon Gathright
# Encode all binary payloads in a given directory using base64 and XOR

import os
import sys
import base64

# encode/decode data with a XOR key
def XOR(data):
    KEY = 0x56 # single-byte key, but it might be changed
    for i,b in enumerate(data):
        data[i] = data[i] ^ KEY
    return data

# Walk through the entire directory tree and encode every file
for root, dirs, files in os.walk(sys.argv[1]):
    for file in files:
        # Read the binary
        data = open(os.path.join(root,file),'rb').read()

        # Encode using base64
        bdata = base64.b64encode(data)

        # XOR the encoded data
        xdata = XOR(bytearray(bdata))

        # store in a new file
        file_loc = "samples\\"
        file_name = file.split(".")[0] + ".enc"
        open(os.path.join(file_loc,file_name),"wb").write(xdata)