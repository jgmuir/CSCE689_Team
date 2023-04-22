# Brandon Gathright
# Convert all strings in the supplied file to ROTX

import sys

# Encode string with ROTX
def ROT(string, x):
    rot_string = ""
    for char in string:
        rot_string += chr((ord(char) + x))
    return rot_string

# Walk through the entire file and encode each string as ROTX
with open(sys.argv[1], 'r') as f:
    reader = f.read()
    lines = reader.split('\n')
    for line in lines:
        if line.strip():
            print(line + " = ", end="")
            rot_line = ROT(line, int(sys.argv[2]))
            idx = 0
            for char in rot_line:
                print(str(ord(char)) + ",", end="")
            print(sys.argv[2])

