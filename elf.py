import struct
import os


class ELFSection:
    SHN_ABS = 0xfff1

    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_SHLIB = 10
    SHT_DYNSYM = 11

    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4

    def __init__(self, segment, name, type, flags, offset_in_segment, size, entry_size):
        self._segment = segment
        self._name = name
        self._name_offset = None
        self._type = type
        self._flags = flags
        self._offset_in_segment = offset_in_segment
        self._size = size
        self._entry_size = entry_size
        self._link = 0
        self._index = None

    @property
    def index(self):
        if self._index is None:
            raise RuntimeError("Section index not yet assigned.")

        return self._index

    @index.setter
    def index(self, value):
        self._index = value

    def resolve_name_offset(self, shstrtab):
        self._name_offset = shstrtab.add_string(self._name)

    def create_elf_section_header(self):
        sh_name = self._name_offset
        sh_type = self._type
        sh_flags = self._flags
        sh_addr = self._segment._addr + self._offset_in_segment if self._segment.program_segment else 0
        sh_offset = self._segment.offset + self._offset_in_segment
        sh_size = self._size if self._size >= 0 else self._segment.length - self._offset_in_segment
        sh_link = self._link
        sh_info = 0
        sh_addralign = 0
        sh_entsize = self._entry_size
        return struct.pack("<10I", sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize)


class ELFSegmentBase:
    PF_X = 1
    PF_W = 2
    PF_R = 4

    def __init__(self):
        self._padding = None
        self._offset = None
        self._addr = None
        self._align = None
        self._flags = None
        self._program_segment = False
        self._sections = []

    def set_as_program_segment(self, address, align, flags):
        self._addr = address
        self._align = align
        self._flags = flags
        self._program_segment = True

    def add_section(self, name, type, flags, offset_in_segment, size, entry_size = 0):
        section = ELFSection(self, name, type, flags, offset_in_segment, size, entry_size)
        self._sections.append(section)

    @property
    def length(self):
        return RuntimeError("Length not specified for segment type")

    @property
    def offset(self):
        if self._offset is None:
            raise RuntimeError("Trying to get segment offset before it was calculated.")
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    @property
    def padding(self):
        if self._padding is None:
            raise RuntimeError("Trying to get segment padding before it was calculated.")
        return self._padding

    @padding.setter
    def padding(self, value):
        self._padding = value

    @property
    def program_segment(self):
        return self._program_segment

    @property
    def sections(self):
        return []

    def resolve_string_offsets(self, strtab):
        pass # most segments doesn't have strings to resolve, but for example symbol table does.

    def create_elf_program_header_for_segment(self):
        if not self.program_segment:
            raise RuntimeError("Program header cannot be created for a non-program segment.")

        p_type = 1 # PT_LOAD
        p_vaddr = self._addr
        p_paddr = self._addr
        p_filesz = self.length
        p_memsz = self.length
        p_flags = self._flags
        p_align = self._align
        return struct.pack("<8I", p_type, self.offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align)


class ELFSegmentFromFile(ELFSegmentBase):
    def __init__(self, file_name, file_offset, segment_size):
        super().__init__()
        self._file_name = file_name
        self._file_offset = file_offset
        file_size = os.path.getsize(file_name)
        if segment_size <= 0:
            segment_size = file_size - file_offset
        elif file_size < file_offset + segment_size:
            raise RuntimeError("Input file smaller than expected. Offset ({}) + segment size ({}) = {} which is more than the file size({})".format(file_offset, segment_size, file_offset+segment_size, file_size))
        self._length = segment_size

    @ELFSegmentBase.length.getter
    def length(self):
        return self._length

    def write_segment_to_file(self, output_file):
        with open(self._file_name, "rb") as input:
            input.seek(self._file_offset)
            wrote_so_far = 0
            data = input.read(4096)
            while wrote_so_far < self._length:
                bytes_to_write = min(self._length - wrote_so_far, len(data))
                wrote_so_far += output_file.write(data[:bytes_to_write])
                data = input.read(4096)


class ELFSegmentFromMemory(ELFSegmentBase):
    def __init__(self):
        super().__init__()
        self._data = bytearray()

    @ELFSegmentBase.length.getter
    def length(self):
        return len(self._data)

    def write_segment_to_file(self, output_file):
        output_file.write(self._data)


class ELFStringTableSegment(ELFSegmentFromMemory):
    def __init__(self, name):
        super().__init__()
        self.add_section(name, ELFSection.SHT_STRTAB, 0, 0, -1)
        self._data.extend(b'\0')

    def add_string(self, str):
        offset = len(self._data)
        self._data.extend(bytes(str, 'ascii') + b'\0')
        return offset


class ELFSymbol:
    STB_LOCAL = 0
    STB_GLOBAL = 1
    STB_WEAK = 2

    STT_NOTYPE = 0
    STT_OBJECT = 1
    STT_FUNC = 2
    STT_SECTION = 3
    STT_FILE = 4
    STT_COMMON = 5

    STV_DEFAULT = 0
    STV_INTERNAL = 1
    STV_HIDDEN = 2
    STV_PROTECTED = 3

    def __init__(self, name, address, size, binding, type, visibility):
        self._name = name
        self._name_offset = None
        self._address = address
        self._size = size
        self._binding = binding
        self._type = type
        self._visibility = visibility

    def resolve_name_offset(self, strtab):
        self._name_offset = strtab.add_string(self._name)

    def create_symbol_entry(self):
        st_name = self._name_offset
        st_value = self._address
        st_size = self._size
        st_info = self._binding *16 + self._type
        st_other = self._visibility
        st_shndx = ELFSection.SHN_ABS
        return struct.pack("<IIIBBH", st_name, st_value, st_size, st_info, st_other, st_shndx)


class ELFSymbolTableSegment(ELFSegmentBase):
    def __init__(self):
        super().__init__()
        self.add_section(".symtab", ELFSection.SHT_SYMTAB, 0, 0, -1, 16)
        self._symbols = []

    @ELFSegmentBase.length.getter
    def length(self):
        return len(self._symbols) * 16

    def add_symbol(self, name, address, size, binding, type, visibility):
        self._symbols.append(ELFSymbol(name, address, size, binding, type, visibility))

    def resolve_string_offsets(self, strtab):
        for symbol in self._symbols:
            symbol.resolve_name_offset(strtab)

    def link_string_table(self, strtab):
        self._sections[0]._link = strtab._sections[0].index

    def write_segment_to_file(self, output_file):
        for symbol in self._symbols:
            output_file.write(symbol.create_symbol_entry())


class ELFModel:

    def __init__(self):
        self.segments = []
        self.e_phoff = 52 # Program header offset. Comes after ELF header, so always 52
        self.e_phentsize = 32 # Program header enty size. Needed to calculate segment offsets
        self.e_shoff = None

        self.strtab = None
        self.shstrtab = None
        self.entry_point = None

    def add_program_segment_from_file(self, file_name, addr, align, file_offset, file_size):
        seg = ELFSegmentFromFile(file_name, file_offset, file_size)
        seg.set_as_program_segment(addr, align, ELFSegmentBase.PF_R + ELFSegmentBase.PF_X)
        self.segments.append(seg)
        return seg

    def add_string_segments(self):
        seg = ELFStringTableSegment(".strtab")
        self.segments.append(seg)
        self.strtab = seg

        seg = ELFStringTableSegment(".shstrtab")
        self.segments.append(seg)
        self.shstrtab = seg

    def add_symtab_segment(self):
        seg = ELFSymbolTableSegment()
        self.segments.append(seg)
        return seg

    @property
    def program_segment_count(self):
        return sum(segment.program_segment for segment in self.segments)

    def assign_section_indices(self):
        idx = 1
        for segment in self.segments:
            for section in segment._sections:
                section.index = idx
                idx += 1

    def build_section_string_table(self):
        if not self.shstrtab:
            raise RuntimeError("Section header string table not yet created.")

        for segment in self.segments:
            for section in segment._sections:
                section.resolve_name_offset(self.shstrtab)

    def build_string_table(self):
        if not self.strtab:
            raise RuntimeError(".strtab string table not yet created.")

        for segment in self.segments:
            segment.resolve_string_offsets(self.strtab)


    def arrange_segments(self):
        program_header_size = self.program_segment_count * self.e_phentsize
        offset = self.e_phoff + program_header_size
        for segment in self.segments:
            if not segment._align or segment._align == 0 or offset % segment._align == 0:
                segment.padding = 0
                segment.offset = offset
            else:
                segment.padding = segment._align - offset % segment._align
                segment.offset = offset + segment.padding
            offset += segment.padding + segment.length
        self.e_shoff = offset

    def link_string_table_to_symbol_table(self, symtab):
        symtab.link_string_table(self.strtab)

    def create_elf_header(self):
        e_ident = struct.pack("<b3s3b9x", 0x7F, b'ELF', 1, 1, 1)
        e_type = 0x02 # ET_EXEC
        e_machine = 0x5e # Tensilica Xtensa Processor
        e_version = 1
        e_entry = self.entry_point
        e_flags = 0x300 # Not sure why, taken from the output of readelf
        e_ehsize = 52
        e_phnum = self.program_segment_count
        e_shentsize = 40
        e_shnum = sum(len(segment._sections) for segment in self.segments) + 1
        e_shstrndx = self.shstrtab._sections[0].index

        return struct.pack("<16sHHIIIIIHHHHHH", e_ident, e_type, e_machine, e_version, e_entry, self.e_phoff, self.e_shoff, e_flags,
                            e_ehsize, self.e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx)

    def write_to_file(self, file_name):
        with open(file_name, "wb") as elf_file:
            elf_file.write(self.create_elf_header())
            for segment in self.segments:
                if segment.program_segment:
                    elf_file.write(segment.create_elf_program_header_for_segment())
            for segment in self.segments:
                if segment.padding > 0:
                    elf_file.write(b'\0' * segment.padding)
                segment.write_segment_to_file(elf_file)

            # first entry is a null entry:
            elf_file.write(struct.pack("<40x"))
            for segment in self.segments:
                for section in segment._sections:
                    elf_file.write(section.create_elf_section_header())

