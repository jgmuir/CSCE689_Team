# Brandon Gathright
# Scrapes all windows executable samples from a user supplied directory and copies them to another user supplied directory with the naming convention XXXX 4-digit number

import pefile
import os
import sys
import shutil

def main():
    # Set the path to start goodware collection
    source_dir = sys.argv[1]

    # Set the path to copy goodware
    output_dir = sys.argv[2]

    # Set the maximum index to collect
    max_idx = int(sys.argv[3])

    # Get the start index for the sample as the maximum sample number in the output directory plus 1
    idx = 0
    if len(os.listdir(output_dir)) != 0:
        idx = max([int(file.split(".")[0]) for file in os.listdir(output_dir)])+1

    # Walk the provided directory and collect all .dll and .exe samples
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            # Stop collecting after the desired number of files have been copied
            if idx > max_idx:
                return
            # Check if the file has the correct extension
            if file.endswith(".dll") or file.endswith(".exe") or file.endswith(".xll"):
                # Check if the file is formatted properly
                try:
                    raw_path = r'{}'.format(os.path.join(root,file))

                    # If this throws no errors the file is good
                    pe = pefile.PE(raw_path)
                    pe.close()

                    # Set the path to save the goodware sample
                    output_path = os.path.join(output_dir, str("{0:0=4d}".format(idx)))

                    # Copy the goodware sample
                    shutil.copyfile(raw_path, output_path)

                    # Increment the current index
                    idx += 1
                except:
                    continue
    return

if __name__ == "__main__":
    main()
