# buildlog_analysis.py
#
# usage: buildlog_analysis.py <directory>
#
# 

import os
import sys

def main():
    '''main function'''
    
    if len(sys.argv) != 2:
        print("Invalid number of arguments")
        sys.exit(1) 

    directory = sys.argv[1]
    if not os.isdir(directory):
        print("path %s does not exist or is a file" % (directory))
        sys.exit(1)
    files = os.listdir(directory)
    
    # traverse the files and analyze the build log contents
    for f in files:
        file_path = os.path.join(directory, f)
        with open(file_path, 'r') as fd:
            fd.
    

if __name__ == "__main__":
	main()
