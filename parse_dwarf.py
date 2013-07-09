# -*- Mode: Python -*-
# Copyright (c) 2002-2011 IronPort Systems and Cisco Systems
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


# Note: this code mistakenly assumes the file it's looking at has the same
#  endianness as the host.  Please fix.

import struct
from pprint import pprint as pp

# DWARF tags
DW_TAG_array_type               = 0x01
DW_TAG_class_type               = 0x02
DW_TAG_entry_point              = 0x03
DW_TAG_enumeration_type         = 0x04
DW_TAG_formal_parameter         = 0x05
DW_TAG_imported_declaration     = 0x08
DW_TAG_label                    = 0x0a
DW_TAG_lexical_block            = 0x0b
DW_TAG_member                   = 0x0d
DW_TAG_pointer_type             = 0x0f
DW_TAG_reference_type           = 0x10
DW_TAG_compile_unit             = 0x11
DW_TAG_string_type              = 0x12
DW_TAG_structure_type           = 0x13
DW_TAG_subroutine_type          = 0x15
DW_TAG_typedef                  = 0x16
DW_TAG_union_type               = 0x17
DW_TAG_unspecified_parameters   = 0x18
DW_TAG_variant                  = 0x19
DW_TAG_common_block             = 0x1a
DW_TAG_common_inclusion         = 0x1b
DW_TAG_inheritance              = 0x1c
DW_TAG_inlined_subroutine       = 0x1d
DW_TAG_module                   = 0x1e
DW_TAG_ptr_to_member_type       = 0x1f
DW_TAG_set_type                 = 0x20
DW_TAG_subrange_type            = 0x21
DW_TAG_with_stmt                = 0x22
DW_TAG_access_declaration       = 0x23
DW_TAG_base_type                = 0x24
DW_TAG_catch_block              = 0x25
DW_TAG_const_type               = 0x26
DW_TAG_constant                 = 0x27
DW_TAG_enumerator               = 0x28
DW_TAG_file_type                = 0x29
DW_TAG_friend                   = 0x2a
DW_TAG_namelist                 = 0x2b
DW_TAG_namelist_item            = 0x2c #  DWARF3/2 spelling
DW_TAG_packed_type              = 0x2d
DW_TAG_subprogram               = 0x2e
DW_TAG_template_type_parameter  = 0x2f #  DWARF3/2 spelling
DW_TAG_template_value_parameter = 0x30 #  DWARF3/2 spelling
DW_TAG_thrown_type              = 0x31
DW_TAG_try_block                = 0x32
DW_TAG_variant_part             = 0x33
DW_TAG_variable                 = 0x34
DW_TAG_volatile_type            = 0x35
DW_TAG_dwarf_procedure          = 0x36  #  DWARF3
DW_TAG_restrict_type            = 0x37  #  DWARF3
DW_TAG_interface_type           = 0x38  #  DWARF3
DW_TAG_namespace                = 0x39  #  DWARF3
DW_TAG_imported_module          = 0x3a  #  DWARF3
DW_TAG_unspecified_type         = 0x3b  #  DWARF3
DW_TAG_partial_unit             = 0x3c  #  DWARF3
DW_TAG_imported_unit            = 0x3d  #  DWARF3
DW_TAG_mutable_type             = 0x3e  #  DWARF3


TAGS = {}
for name in dir():
    if name.startswith ('DW_TAG_'):
        TAGS[eval(name)] = name[7:]


# DWARF attributes
DW_AT_sibling               = 0x01
DW_AT_location              = 0x02
DW_AT_name                  = 0x03
DW_AT_ordering              = 0x09
DW_AT_subscr_data           = 0x0a
DW_AT_byte_size             = 0x0b
DW_AT_bit_offset            = 0x0c
DW_AT_bit_size              = 0x0d
DW_AT_element_list          = 0x0f
DW_AT_stmt_list             = 0x10
DW_AT_low_pc                = 0x11
DW_AT_high_pc               = 0x12
DW_AT_language              = 0x13
DW_AT_member                = 0x14
DW_AT_discr                 = 0x15
DW_AT_discr_value           = 0x16
DW_AT_visibility            = 0x17
DW_AT_import                = 0x18
DW_AT_string_length         = 0x19
DW_AT_common_reference      = 0x1a
DW_AT_comp_dir              = 0x1b
DW_AT_const_value           = 0x1c
DW_AT_containing_type       = 0x1d
DW_AT_default_value         = 0x1e
DW_AT_inline                = 0x20
DW_AT_is_optional           = 0x21
DW_AT_lower_bound           = 0x22
DW_AT_producer              = 0x25
DW_AT_prototyped            = 0x27
DW_AT_return_addr           = 0x2a
DW_AT_start_scope           = 0x2c
DW_AT_stride_size           = 0x2e
DW_AT_upper_bound           = 0x2f
DW_AT_abstract_origin       = 0x31
DW_AT_accessibility         = 0x32
DW_AT_address_class         = 0x33
DW_AT_artificial            = 0x34
DW_AT_base_types            = 0x35
DW_AT_calling_convention    = 0x36
DW_AT_count                 = 0x37
DW_AT_data_member_location  = 0x38
DW_AT_decl_column           = 0x39
DW_AT_decl_file             = 0x3a
DW_AT_decl_line             = 0x3b
DW_AT_declaration           = 0x3c
DW_AT_discr_list            = 0x3d
DW_AT_encoding              = 0x3e
DW_AT_external              = 0x3f
DW_AT_frame_base            = 0x40
DW_AT_friend                = 0x41
DW_AT_identifier_case       = 0x42
DW_AT_macro_info            = 0x43
DW_AT_namelist_item         = 0x44
DW_AT_priority              = 0x45
DW_AT_segment               = 0x46
DW_AT_specification         = 0x47
DW_AT_static_link           = 0x48
DW_AT_type                  = 0x49
DW_AT_use_location          = 0x4a
DW_AT_variable_parameter    = 0x4b
DW_AT_virtuality            = 0x4c
DW_AT_vtable_elem_location  = 0x4d

# these are supposed to be in DWARF3 only, but I'm seeing them
#   in DWARF2 files?
DW_AT_allocated             = 0x4e #  DWARF3
DW_AT_associated            = 0x4f #  DWARF3
DW_AT_data_location         = 0x50 #  DWARF3
DW_AT_stride                = 0x51 #  DWARF3
DW_AT_entry_pc              = 0x52 #  DWARF3
DW_AT_use_UTF8              = 0x53 #  DWARF3
DW_AT_extension             = 0x54 #  DWARF3
DW_AT_ranges                = 0x55 #  DWARF3
DW_AT_trampoline            = 0x56 #  DWARF3
DW_AT_call_column           = 0x57 #  DWARF3
DW_AT_call_file             = 0x58 #  DWARF3
DW_AT_call_line             = 0x59 #  DWARF3
DW_AT_description           = 0x5a #  DWARF3

# DWARF4
DW_AT_description           = 0x5a
DW_AT_binary_scale          = 0x5b
DW_AT_decimal_scale         = 0x5c
DW_AT_small                 = 0x5d
DW_AT_decimal_sign          = 0x5e
DW_AT_digit_count           = 0x5f
DW_AT_picture_string        = 0x60
DW_AT_mutable               = 0x61
DW_AT_threads_scaled        = 0x62
DW_AT_explicit              = 0x63
DW_AT_object_pointer        = 0x64
DW_AT_endianity             = 0x65
DW_AT_elemental             = 0x66
DW_AT_pure                  = 0x67
DW_AT_recursive             = 0x68
DW_AT_signature             = 0x69
DW_AT_main_subprogram       = 0x6a
DW_AT_data_bit_offset       = 0x6b
DW_AT_const_expr            = 0x6c
DW_AT_enum_class            = 0x6d
DW_AT_linkage_name          = 0x6e

# gcc spits this one out at times
DW_AT_MIPS_linkage_name     = 0x2007 # MIPS/SGI

ATS = {}
for name in dir():
    if name.startswith ('DW_AT_'):
        ATS[eval(name)] = name[6:]

DW_ATE_address         = 0x01
DW_ATE_boolean         = 0x02
DW_ATE_complex_float   = 0x03
DW_ATE_float           = 0x04
DW_ATE_signed          = 0x05
DW_ATE_signed_char     = 0x06
DW_ATE_unsigned        = 0x07
DW_ATE_unsigned_char   = 0x08
DW_ATE_imaginary_float = 0x09
DW_ATE_packed_decimal  = 0x0a
DW_ATE_numeric_string  = 0x0b
DW_ATE_edited          = 0x0c
DW_ATE_signed_fixed    = 0x0d
DW_ATE_unsigned_fixed  = 0x0e

ATES = {}
for name in dir():
    if name.startswith ('DW_ATE_'):
        ATES[eval(name)] = name[7:]

# DWARF forms
DW_FORM_addr            = 0x01
DW_FORM_block2          = 0x03
DW_FORM_block4          = 0x04
DW_FORM_data2           = 0x05
DW_FORM_data4           = 0x06
DW_FORM_data8           = 0x07
DW_FORM_string          = 0x08
DW_FORM_block           = 0x09
DW_FORM_block1          = 0x0a
DW_FORM_data1           = 0x0b
DW_FORM_flag            = 0x0c
DW_FORM_sdata           = 0x0d
DW_FORM_strp            = 0x0e
DW_FORM_udata           = 0x0f
DW_FORM_ref_addr        = 0x10
DW_FORM_ref1            = 0x11
DW_FORM_ref2            = 0x12
DW_FORM_ref4            = 0x13
DW_FORM_ref8            = 0x14
DW_FORM_ref_udata       = 0x15
DW_FORM_indirect        = 0x16
# DWARF 4
DW_FORM_sec_offset      = 0x17
DW_FORM_exprloc         = 0x18
DW_FORM_flag_present    = 0x19
DW_FORM_ref_sig8        = 0x20

FORMS = {}
for name in dir():
    if name.startswith ('DW_FORM_'):
        FORMS[eval(name)] = name[8:]

header_spec = '=lhlb'
header_size = struct.calcsize (header_spec)

def read_uleb128 (f):
    "read an 'unsigned little-endian base 128' from <f>"
    result = 0
    shift = 0
    while 1:
        byte = ord (f.read (1))
        result |= (byte & 0x7f) << shift
        if byte & 0x80:
            shift += 7
        else:
            break
    return result

def decode_uleb128 (s):
    "parse an 'unsigned little-endian base 128' from string <s>"
    result = 0
    shift = 0
    i = 0
    while 1:
        byte = ord (s[i]); i += 1
        result |= (byte & 0x7f) << shift
        if byte & 0x80:
            shift += 7
        else:
            break
    return result

def read_string (f):
    "read null-terminated string from <f>"
    r = []
    while 1:
        b = f.read (1)
        if b == '\x00':
            break
        else:
            r.append (b)
    return ''.join (r)

def read_struct (f, s, n):
    "read a struct of size <n> with spec <s> from <f>"
    r = struct.unpack (s, f.read (n))
    if len(r) == 1:
        return r[0]
    else:
        return r

def read_addr (f, psize):
    "read an address of length <psize>"
    if psize == 4:
        return read_struct (f, '=l', 4)
    elif psize == 8:
        return read_struct (f, '=q', 8)
    else:
        raise ValueError, "unsupported pointer size"

def read_block1 (f):
    return f.read (read_struct (f, '=b', 1))
def read_block2 (f):
    return f.read (read_struct (f, '=h', 2))
def read_block4 (f):
    return f.read (read_struct (f, '=l', 4))
def read_block (f):
    return f.read (read_uleb128 (f))
def read_flag (f):
    return not (f.read (1) == '\x00')
def read_data1 (f):
    return read_struct (f, '=B', 1)
def read_data2 (f):
    return read_struct (f, '=H', 2)
def read_data4 (f):
    return read_struct (f, '=L', 4)
def read_data8 (f):
    return read_struct (f, '=Q', 8)
def read_ref1 (f):
    return read_struct (f, '=B', 1)
def read_ref2 (f):
    return read_struct (f, '=H', 2)
def read_ref4 (f):
    return read_struct (f, '=L', 4)
def read_ref_udata (f):
    return read_uleb128 (f)
def read_udata (f):
    return read_uleb128 (f)
def read_flag_present (f):
    return True

def decode_location (x):
    # interpret form
    if x[0] == '#':
        return decode_uleb128 (x[1:])
    elif x[0] == '\x91':
        # XXX signed, but we'll cheat
        return decode_uleb128 (x[1:])
    elif x[0] == '\x03':
        # DW_OP_ADDR
        x = x[1:]
        if len(x) == 4:
            return struct.unpack ('=l', x)[0]
        elif len(x) == 8:
            return struct.unpack ('=q', x)[0]
        else:
            return 'DW_OP_ADDR:%s' % (x.encode ('hex'))
    else:
        return x

form_readers = {
    DW_FORM_string:     read_string,
    DW_FORM_data1:      read_data1,
    DW_FORM_data2:      read_data2,
    DW_FORM_data4:      read_data4,
    DW_FORM_data8:      read_data8,
    DW_FORM_ref1:       read_ref1,
    DW_FORM_ref2:       read_ref2,
    DW_FORM_ref4:       read_ref4,
    DW_FORM_ref4:       read_ref4,
    DW_FORM_ref_udata:  read_ref_udata,
    DW_FORM_block1:     read_block1,
    DW_FORM_block2:     read_block2,
    DW_FORM_block4:     read_block4,
    DW_FORM_flag:       read_flag,
    DW_FORM_udata:      read_udata,
    # XXX: HACK - I'm too lazy to figure out
    #      how to sign-extend these numbers.
    DW_FORM_sdata:      read_udata,
    DW_FORM_flag_present: read_flag_present, # DWARF4
    }

class section:

    def __init__ (self, path, offset, size):
        self.path = path
        self.file = open (path, 'rb')
        self.offset = offset
        self.size = size
        self.file.seek (offset)

    def __repr__ (self):
        return '<%s "%s" at 0x%x>' % (self.__class__.__name__, self.path, id(self))

class string_section (section):

    def get (self, pos):
        self.file.seek (self.offset + pos)
        return read_string (self.file)

class abbrev_section (section):

    def read_cu (self):
        "read a compilation unit entry from an abbrev section"
        tag   = read_uleb128 (self.file)
        child = ord (self.file.read (1))
        attrs = []
        while 1:
            attr  = read_uleb128 (self.file)
            form  = read_uleb128 (self.file)
            if (attr, form) == (0, 0):
                break
            else:
                attrs.append ((attr, form))
        return tag, child, attrs

    def read (self, offset):
        "read abbrev table at <offset>"
        self.file.seek (self.offset + offset)
        abbrevs = {}
        while 1:
            index = read_uleb128 (self.file)
            if index == 0:
                break
            else:
                abbrevs[index] = self.read_cu()
        return abbrevs

class info_section (section):

    def read_all (self, abbrevs, strings):
        "generate a list of compile_unit objects"
        # Made this an iterator because collecting all the
        #   debug info from a typical python binary eats up
        #   about 100MB of memory!  Iterating over it one
        #   compile_unit at a time is much more manageable
        while 1:
            where = self.file.tell()
            if where >= self.offset + self.size:
                break
            else:
                tree, by_pos = self.read (abbrevs, strings)
                yield (compile_unit (tree, by_pos))

    def read (self, abbrevs, strings):
        base = self.file.tell()
        self.header = struct.unpack (header_spec, self.file.read (header_size))
        self.length, self.version, self.abbr_offset, self.psize = self.header
        if self.version > 2:
            raise ValueError
        abbrev_table = abbrevs.read (self.abbr_offset)
        by_pos = {}
        tree = self.read_tree (abbrev_table, strings, by_pos, 0, base)
        return tree, by_pos

    def read_tree (self, abbrev_table, strings, by_pos, depth, base):
        f = self.file
        tree = []
        while 1:
            where = f.tell() - base
            index = read_uleb128 (f)
            if not index:
                # null index indicates the end of a list of siblings
                return tree
            # NOTE: each item in a list of siblings has a 'DW_AT_sibling'
            #   telling you the location of the next record.  This can be
            #   used to skip over types you don't know or care about.
            attrs = {}
            tag, child, attr_forms = abbrev_table[index]
            for attr, form in attr_forms:
                # strp & addr are special-cased because they
                #   need extra context...
                if form == DW_FORM_strp:
                    x = strings.get (read_struct (f, '=l', 4))
                elif form == DW_FORM_addr:
                    x = read_addr (f, self.psize)
                else:
                    x = form_readers[form](f)
                # special-case these, which technically require interpreters
                #   for the stack language.  however, gcc seems to only output
                #   the uleb128 & sleb128 versions...
                if attr in (DW_AT_data_member_location, DW_AT_location):
                    if isinstance (x, str):
                        x = decode_location (x)
                    elif isinstance (x, int):
                        pass
                    else:
                        raise ValueError ("unexpected type in DW_AT_data_member_location/DW_AT_location")
                try:
                    attrs[ATS[attr]] = x
                except KeyError:
                    # lots of vendor-specific extensions
                    attrs[hex(attr)] = x
            if child:
                # recursively read the list of children of this node
                children = self.read_tree (abbrev_table, strings, by_pos, depth + 1, base)
            else:
                children = None
            if TAGS.has_key (tag):
                item = (TAGS[tag], where, attrs, children)
            else:
                item = (tag, where, attrs, children)
            by_pos[where] = item
            tree.append (item)
            if depth == 0:
                # only one element at the top level, special-case it
                return item
        return tree

class compile_unit:

    def __init__ (self, tree, by_pos):
        self.tree = tree
        tag, where, self.attrs, self.children = tree
        assert (tag == 'compile_unit')
        self.by_pos = by_pos

    def __repr__ (self):
        return '<compile_unit %r at 0x%x>' % (self.attrs['name'], id(self))

    def dump (self, file):
        self.dump_tree (file, self.tree, 0)

    def __getitem__ (self, pos):
        return self.by_pos[pos]

    def dump_tree (self, file, ob, depth):
        tag, where, attrs, children = ob
        print '%6d%s %s' % (where, '  ' * depth, tag),
        for attr, data in attrs.iteritems():
            print '%s:%r' % (attr, data),
        print
        if children:
            for child in children:
                self.dump_tree (file, child, depth + 1)

# http://dwarfstd.org/dwarf-2.0.0.pdf
# see pg 95 for a good example of the relationship between the different sections
# see pg 71/72 for descriptions of DW_FORMs
# location descriptions: start on page 72, hopefully we don't need to implement
#   the whole stack machine thing.  Most of the offsets appear to be simple
#   DW_OP_plus_uconst ('#'/0x23), which encodes as a uleb128

def read (path, elf_info):
    """read (<path>, <elf_info>) => <iterator>
    generate a list of <compile_unit> objects for file <path>"""
    ehdr, phdrs, shdrs, syms, core_info = elf_info
    info = abbrev = strings = None
    for shdr in shdrs:
        if shdr['name'] == '.debug_info':
            info = shdr['offset'], shdr['size']
        if shdr['name'] == '.debug_abbrev':
            abbrev = shdr['offset'], shdr['size']
        if shdr['name'] == '.debug_str':
            strings = shdr['offset'], shdr['size']
    if not info:
        return []
    else:
        abbrevs = abbrev_section (path, abbrev[0], abbrev[1])
        if strings:
            strings = string_section (path, strings[0], strings[1])
        info = info_section (path, info[0], info[1])
        return info.read_all (abbrevs, strings)

def test (path):
    import parse_elf
    import sys
    global info
    info_iter = read (path, parse_elf.go (path))
    if not info_iter:
        sys.stderr.write ('no debugging information present\n')
    else:
        for unit in info_iter:
            print '-' * 75
            unit.dump (sys.stdout)

if __name__ == '__main__':
    import sys
    test (sys.argv[1])
