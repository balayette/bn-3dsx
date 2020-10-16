import struct

from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.log import *

from binaryninja.enums import SegmentFlag, SectionSemantics

def u16(b):
    return struct.unpack("H", b)[0]

def u32(b):
    return struct.unpack("I", b)[0]

def align(v, b):
    return (v + b) & ~b

class View(BinaryView):
    name = "3DSX ROM"
    long_name = "3DSX ROM"

    BASE_ADDR = 0x108000

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture["armv7"].standalone_platform
        self.data = data
        self.offt = 0

    @classmethod
    def is_valid_for_data(self, data):
        sig = data.read(0, 4)
        if sig != b"3DSX":
            return False

        return True

    def init(self):
        offt = 0
        offt += 4 # skip magic

        hdr_sz = u16(self.parent_view.read(offt, 2))
        offt += 2
        rel_hdr_sz = u16(self.parent_view.read(offt, 2))
        offt += 2
        fmt_ver = u32(self.parent_view.read(offt, 4))
        offt += 4
        flags = u32(self.parent_view.read(offt, 4))
        offt += 4
        code_sz = u32(self.parent_view.read(offt, 4))
        offt += 4
        rodata_sz = u32(self.parent_view.read(offt, 4))
        offt += 4
        data_sz = u32(self.parent_view.read(offt, 4))
        offt += 4
        bss_sz = u32(self.parent_view.read(offt, 4))
        offt += 4

        has_extended_header = hdr_sz > 32
        if has_extended_header:
            offt += 12

        reloc_headers = []

        # code relocation header
        reloc_headers.append(offt)
        offt += 8
        # rodata relocation header
        reloc_headers.append(offt)
        offt += 8
        # data relocation header
        reloc_headers.append(offt)
        offt += 8

        segment_bases = []

        addr = self.BASE_ADDR
        # code segment here
        code_virtual_size = align(code_sz, 0xfff)
        self.add_auto_segment(addr, code_virtual_size, offt, code_sz,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        self.add_auto_section("code", addr, code_virtual_size,
                SectionSemantics.ReadOnlyCodeSectionSemantics)
        segment_bases.append(addr)
        addr += code_virtual_size
        offt += code_sz

        # rodata segment here
        rodata_virtual_size = align(rodata_sz, 0xfff)
        self.add_auto_segment(addr, rodata_virtual_size, offt, rodata_sz,
                SegmentFlag.SegmentReadable)
        self.add_auto_section("rodata", addr, rodata_virtual_size,
                SectionSemantics.ReadOnlyDataSectionSemantics)
        segment_bases.append(addr)
        addr += rodata_virtual_size
        offt += rodata_sz

        # data segment here
        data_virtual_size = align(data_sz, 0xfff)
        self.add_auto_segment(addr, data_virtual_size, offt, data_sz - bss_sz,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_auto_section("data", addr, data_sz - bss_sz,
                SectionSemantics.ReadWriteDataSectionSemantics)
        self.add_auto_section("bss", addr + data_sz - bss_sz, bss_sz,
                SectionSemantics.ReadWriteDataSectionSemantics)
        segment_bases.append(addr)
        addr += data_virtual_size
        offt += data_sz - bss_sz

        relocation_table = offt

        for i in range(len(reloc_headers)):
            rel_hdr = reloc_headers[i]
            patch_addr = segment_bases[i]

            abs_count = u32(self.parent_view.read(rel_hdr, 4))
            rel_count = u32(self.parent_view.read(rel_hdr + 4, 4))

            for j in range(abs_count):
                skip = u16(self.parent_view.read(relocation_table, 2))
                npatch = u16(self.parent_view.read(relocation_table + 2, 2))
                relocation_table += 4

                patch_addr += 4 * skip

                for p in range(npatch):
                    addr = u32(self.read(patch_addr, 4))
                    addr += segment_bases[i]
                    self.write(patch_addr, struct.pack("I", addr))
                    patch_addr += 4

            for j in range(rel_count):
                skip = u16(self.parent_view.read(relocation_table, 2))
                npatch = u16(self.parent_view.read(relocation_table + 2, 2))
                relocation_table += 4

                patch_addr += 4 * skip

                for p in range(npatch):
                    addr = u32(self.read(patch_addr, 4))
                    addr += segment_bases[i] - patch_addr
                    self.write(patch_addr, struct.pack("I", addr))
                    patch_addr += 4


        self.add_entry_point(self.BASE_ADDR)

        return True
