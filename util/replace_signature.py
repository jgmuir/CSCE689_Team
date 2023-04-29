# Brandon Gathright
# Changes the NT_HEADER signature for every PE file in the directory
# Hide by changing to 0
# Fix by changing to 17744

import os
import sys
import pefile

def main():
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    signature = int(sys.argv[3])
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            try:
                pe = pefile.PE(os.path.join(root, file))
                pe.NT_HEADERS.Signature = signature
                pe.write(os.path.join(output_dir, file))
                pe.close()
            except:
                continue

if __name__ == '__main__':
    main()

