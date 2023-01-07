import struct
import os
import re

from elf import ELFSymbolTableSegment, ELFSymbol, ELFModel, ELFSection

def read_symbols_from_ld(symtab: ELFSymbolTableSegment):
    matcher = re.compile(r"PROVIDE *[(] *([^ ]+) *= *([^ ]+) *[)];")
    with open("eagle.rom.addr.v6.ld", "r") as ld_file:
        for line in ld_file:
            res = matcher.match(line)
            if res:
                name = res.group(1)
                address = int(res.group(2), 16)
                symtab.add_symbol(name, address, 0, ELFSymbol.STB_GLOBAL, ELFSymbol.STT_FUNC, ELFSymbol.STV_DEFAULT)


def analyse_flash_data(bootloader: bool):
    with open("flash.bin", "rb") as flash_file:

        if not bootloader:
            flash_file.seek(0x1000)

        segments = [] # list of (offset, length, target_addr)


        image_header = flash_file.read(8)
        (magic, num_sections, flash_mode, flash_size_freq, entry_point) = struct.unpack("<BBBBI", image_header)
        print("Magic: 0x{:02x}, number of sections: {}, flash mode: 0x{:02x}, flash size and frequency: 0x{:02x}, entry: 0x{:08x}".format(magic, num_sections, flash_mode, flash_size_freq, entry_point))
        if magic != 0xe9:
            print("Not an image header.")
        else:
            for i in range(num_sections):
                section_header = flash_file.read(8)
                (address, size) = struct.unpack("<II", section_header)
                print("Section #{} starting at 0x{:08x} size {:08x}".format(i, address, size))
                segments.append((flash_file.tell(), size, address))
                flash_file.seek(size, 1)

        return (entry_point, segments)




def main():


    elf = ELFModel()
    seg = elf.add_program_segment_from_file("rom.bin", 0x40000000, 1, 0, 0)
    seg.add_section(".text", ELFSection.SHT_PROGBITS, ELFSection.SHF_ALLOC + ELFSection.SHF_EXECINSTR, 0, -1)

    (elf.entry_point, flash_segments) = analyse_flash_data(False)
    index = 0
    for (offset, size, address) in flash_segments:
        seg = elf.add_program_segment_from_file("flash.bin", address, 1, offset, size)
        seg.add_section(".flash{}".format(index), ELFSection.SHT_PROGBITS, ELFSection.SHF_ALLOC + ELFSection.SHF_EXECINSTR, 0, -1)
        index += 1

    elf.add_string_segments()

    symtab = elf.add_symtab_segment()
    read_symbols_from_ld(symtab)

    elf.build_string_table()
    elf.build_section_string_table()

    elf.arrange_segments()
    elf.assign_section_indices()
    elf.link_string_table_to_symbol_table(symtab)

    elf.write_to_file("rom.elf")

if __name__ == "__main__":
    main()
