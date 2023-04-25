# Brandon Gathright
# Checks every file in the directory if it passes yasir's model by breaking the is_probably_packed test

import os
import sys
import pefile

def main():
    for root, dirs, files in os.walk(sys.argv[1]):
        for file in files:
            try:
                pe = pefile.PE(os.path.join(root, file))
                if is_probably_packed(pe):
                    result = 1
            except:
                result = 0
            if result == 0:
                print("Sample " + str(file) + " evades yasir's model")
            else:
                print("Sample " + str(file) + " fails yasir's model")

def is_probably_packed(pe):
    total_pe_data_length = len(pe.trim())
    if not total_pe_data_length:
        return True
    has_significant_amount_of_compressed_data = False
    total_compressed_data = 0
    for section in pe.section:
        s_entropy = section.get_entropy()
        s_length = len(section.get_data())
        if s_entropy > 7.4:
            total_compressed_data += s_length
    if ((1.0 * total_compressed_data) / total_pe_data_length) > 0.2:
        has_significant_amount_of_compressed_data = True
    return has_significant_amount_of_compressed_data    

if __name__ == '__main__':
    main()
