# Brandon Gathright
# Remove extensions from every file in the supplied directory

import os
import sys

def main():
    for root, dirs, files in os.walk(sys.argv[1]):
        for file in files:
            if (len(file.split('.')) > 1):
                new_file = ''.join(file.split('.')[0:len(file.split('.'))-1])
                os.rename(os.path.join(root,file), os.path.join(root,new_file))
    return

if __name__ == '__main__':
    main()