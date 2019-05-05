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
    csv_writer.writerow(["package", "type", "count"])
    print("lines:")
    for k in sorted(file_gcc_lines):
        print("%s = %s" % (k, file_gcc_lines[k]))
        row = []
        num_gcc = len(file_gcc_lines[k])
        num_stack_protector = 0
        num_stack_protector_strong = 0
        num_stack_protector_all = 0
        num_no_stack_protector = 0
        for gcc in file_gcc_lines[k]:
            if '-fstack-protector ' in gcc:
                num_stack_protector += 1
            elif '-fstack-protector-strong' in gcc:
                num_stack_protector_strong += 1
            elif '-fstack-protector-all' in gcc:
                num_stack_protector_all += 1
            elif '-fno-stack-protector':
                num_no_stack_protector += 1
        row_num_gcc = [k, "num_gcc", num_gcc]
        row_num_stack_protector = [k, "num_stack_protector", num_stack_protector]
        row_num_stack_protector_strong = [k, "num_stack_protector_strong", num_stack_protector_strong]
        row_num_stack_protector_all = [k, "num_stack_protector_all", num_stack_protector_all]
        row_num_no_stack_protector = [k, "num_no_stack_protector", num_no_stack_protector]
        
        csv_writer.writerow(row_num_gcc)
        csv_writer.writerow(row_num_stack_protector)
        csv_writer.writerow(row_num_stack_protector_strong)
        csv_writer.writerow(row_num_stack_protector_all)
        csv_writer.writerow(row_num_no_stack_protector)
    csvfd.close()
    

if __name__ == "__main__":
    main()
