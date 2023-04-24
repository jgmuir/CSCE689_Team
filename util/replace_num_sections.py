# Brandon Gathright
# Changes the number of sections for every PE file in the directory

import os
import sys
import pefile

def main():
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    section_count = int(sys.argv[3])
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            try:
                pe = pefile.PE(os.path.join(root, file))
                pe.FILE_HEADER.NumberOfSections = section_count
                pe.write(os.path.join(output_dir, file))
                pe.close()
            except:
                continue

if __name__ == '__main__':
    main()

