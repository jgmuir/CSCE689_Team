# Brandon Gathright
# Copy all samples from a user supplied directory and another user supplied directory with the naming convention XXXX 4-digit number

import sys
import os
import shutil

def main():
    # Set the input directory to copy samples from
    input_dir = sys.argv[1]

    # Set the output directory to copy samples to
    output_dir = sys.argv[2]

    # Get the start index for the sample as the maximum sample number in the output directory plus 1
    idx = 0
    if len(os.listdir(output_dir)) != 0:
        idx = max([int(file.split(".")[0]) for file in os.listdir(output_dir)])+1

    # Rename the samples to the corresponding index
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            # If the file is a windows executable
                #if file.endswith(".exe") or file.endswith(".dll") or file.endswith(".xll"):
                    # Copy the file to the output directory
                shutil.copyfile(os.path.join(root, file), os.path.join(output_dir, "{0:0=4d}".format(idx)))
                idx += 1
    return

if __name__ == "__main__":
    main()