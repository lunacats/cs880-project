# static_analysis.py
#
# Performs static analysis of Linux ELF binaries.
#
# Returns the number of function calls in the binary and
# the number protected by stack overflow canaries.
#
# Usage:
# static_analysis.py [OPTIONS] <ELF binary>
#   Options:
#       --verbose:      prints verbose details of the
#                       ELF symbol table
#
#

import argparse
import os
import sys
from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.sections import NullSection

stack_check_sections = ["__stack_chk_fail", "__stack_smash_handler"]


def main():
    '''main function'''
    # argument parsing
    parser = argparse.ArgumentParser(description='ELF binary stack protection parser')
    parser.add_argument('file_path', nargs=1)
    parser.add_argument('--verbose', dest='verbose', action='store_true')
    parser.add_argument('--stack-protect-check', dest='stack_protect_check', action='store_true')

    args = parser.parse_args()
    # print(args)
    
    file_path = args.file_path[0]
    verbose = args.verbose
    stack_protect_check = args.stack_protect_check
    
    if not os.path.isfile(file_path):
        print("Invalid file path, file does not exist or is a directory")
        sys.exit(2)

    # open the file and create the ELFFile object
    fd = open(file_path, 'rb')
    elffile = ELFFile(fd)

    # sections
    symbol_table_sections = []
    relocation_sections = []
    for section in elffile.iter_sections():
        # show all section data
        if isinstance(section, SymbolTableSection):
            symbol_table_sections.append(section)
        elif isinstance(section, RelocationSection):
            relocation_sections.append(section)

    print("SYMBOL TABLE SECTIONS:")
    for section in symbol_table_sections:
        print("%s symbols:" % section.name)
        print("\tnumber - name")
        for i, symbol in enumerate(section.iter_symbols()):
            if symbol.name is not None:
                print("\t%s - %s - %s" % (i, symbol.name))

    print("RELOCATION SECTIONS:")
    for section in relocation_sections:
        print('%s:' % section.name)
        symbol_table = section.get_section(section['sh_link'])
        for relocation in section.iter_relocations():
            symbol = symbol_table.get_symbol(relocation['r_info_sym'])
            addr = hex(relocation['r_offset'])
            print("%s 0x%x" % (symbol.name, addr))

    # disassemble
    print("DISASSEMBLY:")
    code = elffile.get_section_by_name('.text')
    opcodes = code.data()
    addr = code['sh_addr']
    print("Entry Point: %s" % (hex(elffile.header['e_entry'])))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(opcodes, addr):
        print("0x%x:\t\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


def print_help():
    '''prints a help message'''
    print("Usage: static_analysis.py [--verbose|--stack-protect-check] <ELF binary file>")


if __name__ == "__main__":
    main()

