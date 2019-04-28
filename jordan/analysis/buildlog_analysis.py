# buildlog_analysis.py
#
# usage: buildlog_analysis.py <directory>
#

import csv
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
        with open(file_path, 'r', encoding='ISO-8859-1') as fd:
            try:
                raw_text = fd.read()
            except UnicodeDecodeError as err:
                print("UnicodeDecodeError %s in %s" % (err, file_path))
            lines = raw_text.splitlines()

        # process line-by-line
        gcc_lines = []
        for l in lines:
            if 'gcc' in l[0:3]:
                gcc_lines.append(l)

        file_gcc_lines[f] = gcc_lines

    # analyze the gcc lines for each file
    # name, num gcc, num_stack_protector, num_stack_protector_strong, num_stack_protector_all, num_no_stack_protection
    csvfd = open("buildlog_analysis.csv", 'w', newline='')
    csv_writer = csv.writer(csvfd, dialect='excel')
    csv_writer.writerow(["package", "num_gcc", "stack_protector", "stack_protector_strong", "stack_protector_all", "no_stack_protection"])
    print("lines:")
    for k in sorted(file_gcc_lines):
        print("%s = %s" % (k, file_gcc_lines[k]))
        row = []
        num_gcc = len(file_gcc_lines[k])
        num_stack_protector = 0
        num_stack_protector_strong = 0
        num_stack_protector_all = 0
        num_no_stack_protection = 0
        for gcc in file_gcc_lines[k]:
            if '-fstack-protector ' in gcc:
                num_stack_protector += 1
            elif '-fstack-protector-strong' in gcc:
                num_stack_protector_strong += 1
            elif '-fstack-protector-all' in gcc:
                num_stack_protector_all += 1
            else:
                num_no_stack_protection += 1
        row = [k,
               num_gcc, 
               num_stack_protector, 
               num_stack_protector_strong, 
               num_stack_protector_all, 
               num_no_stack_protection]
        csv_writer.writerow(row)
    csvfd.close()
    

if __name__ == "__main__":
    main()
