# Brandon Gathright
# This script takes the list of resources in the input directory and compiles them using the project in the visual studio directory, and stores the resulting executables in the output directory

import os
import sys
import shutil

def main():
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    visual_studio_project_dir = sys.argv[3]

    visual_studio_solution_loc = visual_studio_project_dir + "\\Dropper.sln"
    visual_studio_resource_loc = visual_studio_project_dir + "\\resource"
    visual_studio_compiled_loc = visual_studio_project_dir + "\\Release\\Dropper.exe"
    visual_studio_cache_files_1 = visual_studio_project_dir + "\\Dropper\\Release\\"
    visual_studio_cache_files_2 = visual_studio_project_dir + "\\Release\\"

    for root, dirs, files in os.walk(input_dir):
        for file in files:
            # Read the resource data from the current file
            data = open(os.path.join(root,file),'rb').read()

            # Write the current data to the VS resource location
            open(visual_studio_resource_loc, 'wb').write(data)

            # Use MSBuild to compile the current project file
            os.system(f'msbuild {visual_studio_solution_loc} /p:Configuration=Release /p:Platform=x86')

            # Copy the compiled binary to the output directory
            os.rename(visual_studio_compiled_loc, os.path.join(output_dir, file))

            # Delete the cached files
            shutil.rmtree(visual_studio_cache_files_1)
            shutil.rmtree(visual_studio_cache_files_2)

if __name__ == '__main__':
    main()