# Brandon Gathright
# Unzip all samples from a user supplied directory and another user supplied directory with the naming convention XXXX 4-digit number

import os
import sys
import shutil
import pyzipper

def main():
    # Set the path to the source directory containing zipped samples
    input_dir = sys.argv[1]

    # Set the path to the destination directory for the unzipped samples
    output_dir = sys.argv[2]

    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    # Get the start index for the sample as the maximum sample number in the output directory plus 1
    idx = 0
    if len(os.listdir(output_dir)) != 0:
        idx = max([int(file.split(".")[0]) for file in os.listdir(output_dir)])+1
            
    # Define hard-coded constants
    ZIP_PASSWORD = b'infected'

    # Iterate through all files in the input directory
    for file in os.listdir(input_dir):
        if file.endswith(".zip"):
            # Create a temporary directory for unzipping the file
            temp_dir = input_dir + "/" + file.split(".")[0] + "/"
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            os.mkdir(temp_dir)

            # Unzip the file
            with pyzipper.AESZipFile(os.path.join(input_dir, file)) as zf:
                zf.pwd = ZIP_PASSWORD
                my_secrets = zf.extractall(temp_dir)
            os.remove((os.path.join(input_dir, file)))

            # Check all files in the unzipped temp directory
            for temp_file in os.listdir(temp_dir):
                # If the file is a windows executable
                if temp_file.endswith(".exe") or temp_file.endswith(".dll") or temp_file.endswith(".xll"):
                    # Set the path to save the unzipped file
                    output_path = os.path.join(output_dir, str("{0:0=4d}".format(idx)))

                    # Move the unzipped file to the output directory
                    shutil.copyfile(os.path.join(temp_dir, temp_file), output_path)
                    idx += 1
            shutil.rmtree(temp_dir)
    return

if __name__ == "__main__":
    main()