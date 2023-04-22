import os
import sys
import shutil

def main():
    # Set the path to start goodware collection
    source_dir = sys.argv[1]
    print(source_dir)
    # Set the path to copy goodware
    output_dir = sys.argv[2]

    # Get the start index for the sample as the maximum sample number in the output directory plus 1
    idx = 0
    if len(os.listdir(output_dir)) != 0:
        idx = max([int(file.split(".")[0]) for file in os.listdir(output_dir)])+1

    # Walk the provided directory and collect all .dll and .exe samples
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            if file.endswith(".dll") or file.endswith(".exe"):
                # Set the path to save the goodware sample
                output_path = os.path.join(output_dir, str("{0:0=4d}".format(idx)))

                # Copy the goodware sample
                shutil.copyfile(os.path.join(root, file), output_path)

                # Increment the current index
                idx += 1
    return

if __name__ == "__main__":
    main()
