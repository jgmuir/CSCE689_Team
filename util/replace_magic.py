# Brandon Gathright
# Changes the DOS_HEADER e_magic for every PE file in the directory
# Hide by changing to 0
# Fix by changing to 23117

import os
import sys
import pefile

def main():
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    magic = int(sys.argv[3])
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            try:
                pe = pefile.PE(os.path.join(root, file))
                pe.DOS_HEADER.e_magic = magic
                pe.write(os.path.join(output_dir, file))
                pe.close()
            except:
                continue

if __name__ == '__main__':
    main()

