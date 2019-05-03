# static_analysis.py
#
# Performs static analysis of Linux ELF binaries.
#
# Returns the number of function calls in the binary and
# the number protected by stack overflow canaries.
#

import os
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.sections import NullSection

stack_check_sections = ["__stack_chk_fail", "__stack_smash_handler"]


def main():
    '''main function'''

    if len(sys.argv) != 2:
        print("Invalid number of arguments.")
        print_help()
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        print("Invalid file path, file does not exist or is a directory")
        sys.exit(2)

    # open the file and create the ELFFile object
    fd = open(file_path, 'rb')
    elffile = ELFFile(fd)

    # sections
    print("SYMBOLTABLE SECTIONS:")
    for section in elffile.iter_sections():
        # show all section data
        if isinstance(section, SymbolTableSection):
            print("symbols:")
            for i, symbol in enumerate(section.iter_symbols()):
                print("\t%s - %s" % (i, symbol))
            


def print_help():
    '''prints a help message'''
    print("Usage: static_analysis.py <ELF binary file>")


if __name__ == "__main__":
    main()

