# Brandon Gathright
# Renumbers all samples from a user supplied directory with the naming convention XXXX 4-digit number

import os
import sys
import shutil

def main():
    # Set the input directory for file renaming
    input_dir = sys.argv[1]

    # Create a temporary directory to store all the file while they are renamed
    temp_dir = "/temp/"
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.mkdir(temp_dir)

    # Set the start index for the renumbering to 0
    idx = 0

    # Renumber every file in the directory
    for file in os.listdir(input_dir):
        os.rename(os.path.join(input_dir, file), os.path.join(temp_dir, str("{0:0=4d}".format(idx))))
        idx += 1

    # Remove the existing input directory
    shutil.rmtree(input_dir)

    # Copy the temp directory to the input directory
    shutil.copytree(temp_dir, input_dir)

    # Remove the temp directory
    shutil.rmtree(temp_dir)

    return

if __name__ == "__main__":
    main()