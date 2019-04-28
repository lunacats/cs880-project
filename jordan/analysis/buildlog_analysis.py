# buildlog_analysis.py
#
# usage: buildlog_analysis.py <directory>
#


import os
import sys

def main():
    '''main function'''
    
    if len(sys.argv) != 2:
        print("Invalid number of arguments")
        sys.exit(1) 

    directory = sys.argv[1]
    if not os.path.isdir(directory):
        print("path %s does not exist or is a file" % (directory))
        sys.exit(1)
    files = os.listdir(directory)
    
    # traverse the files and analyze the build log contents
    file_gcc_lines = {}
    for f in files:
        file_path = os.path.join(directory, f)
        with open(file_path, 'r') as fd:
            raw_text = fd.read()
            lines = raw_text.splitlines()

        # process line-by-line
        gcc_lines = []
        for l in lines:
            if 'gcc' in l[0:3]:
                gcc_lines.append(l)

        file_gcc_lines[f] = gcc_lines

    # analyze the gcc lines for each file
    print("lines:")
    for k in sorted(file_gcc_lines):
        print("%s = %s" % (k, file_gcc_lines[k]))

    

if __name__ == "__main__":
    main()
