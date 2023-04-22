import sys
import os

source_dir = sys.argv[1]
dest_dir = sys.argv[2]
last_idx = max([int(file) for file in os.listdir(sys.argv[2])])+1
[os.rename(os.path.join(sys.argv[1], file), os.path.join(sys.argv[2], "{0:0=4d}".format(int(file.split(".")[0]) + last_idx))) for file in os.listdir(sys.argv[1])]