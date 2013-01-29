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


# This parser assumes little-endian, but it can handle either 32 or 64 bit
# files.  The endian thing should be easy to fix, though - see the '<' prefix
# on each of the struct specs below.

import pprint
import struct

# default to no output
report_out = None

EI_MAG0         = 0     #  Magic number, byte 0.
EI_MAG1         = 1     #  Magic number, byte 1.
EI_MAG2         = 2     #  Magic number, byte 2.
EI_MAG3         = 3     #  Magic number, byte 3.
EI_CLASS        = 4     #  Class of machine.
EI_DATA         = 5     #  Data format.
EI_VERSION      = 6     #  ELF format version.
EI_OSABI        = 7     #  Operating system / ABI identification
EI_ABIVERSION   = 8     #  ABI version
OLD_EI_BRAND    = 8     #  Start of architecture identification.
EI_PAD          = 9     #  Start of padding (per SVR4 ABI).
EI_NIDENT       = 16    #  Size of e_ident array.

# base types from elf32.h:
# typedef u_int32_t     Elf32_Addr;
# typedef u_int16_t     Elf32_Half;
# typedef u_int32_t     Elf32_Off;
# typedef int32_t       Elf32_Sword;
# typedef u_int32_t     Elf32_Word;
# typedef u_int32_t     Elf32_Size;
# typedef Elf32_Off     Elf32_Hashelt;

# 32-bit header:
#            typedef struct {
#                    unsigned char   e_ident[EI_NIDENT];
#                    Elf32_Half      e_type;
#                    Elf32_Half      e_machine;
#                    Elf32_Word      e_version;
#                    Elf32_Addr      e_entry;
#                    Elf32_Off       e_phoff;
#                    Elf32_Off       e_shoff;
#                    Elf32_Word      e_flags;
#                    Elf32_Half      e_ehsize;
#                    Elf32_Half      e_phentsize;
#                    Elf32_Half      e_phnum;
#                    Elf32_Half      e_shentsize;
#                    Elf32_Half      e_shnum;
#                    Elf32_Half      e_shstrndx;
#            } Elf32_Ehdr;

elf32_ehdr = '<HHLLLLLHHHHHH'

# base types from elf64.h:
# typedef u_int64_t     Elf64_Addr;
# typedef u_int32_t     Elf64_Half;
# typedef u_int64_t     Elf64_Off;
# typedef int64_t       Elf64_Sword;
# typedef u_int64_t     Elf64_Word;
# typedef u_int64_t     Elf64_Size;
# typedef u_int16_t     Elf64_Quarter;

# 64-bit header
#            typedef struct {
#                    unsigned char   e_ident[EI_NIDENT];
#                    Elf64_Quarter   e_type;
#                    Elf64_Quarter   e_machine;
#                    Elf64_Half      e_version;
#                    Elf64_Addr      e_entry;
#                    Elf64_Off       e_phoff;
#                    Elf64_Off       e_shoff;
#                    Elf64_Half      e_flags;
#                    Elf64_Quarter   e_ehsize;
#                    Elf64_Quarter   e_phentsize;
#                    Elf64_Quarter   e_phnum;
#                    Elf64_Quarter   e_shentsize;
#                    Elf64_Quarter   e_shnum;
#                    Elf64_Quarter   e_shstrndx;
#            } Elf64_Ehdr;

elf64_ehdr = '<HHLQQQLHHHHHH'

def parse_ehdr (format, data):
    (type, machine, version, entry, phoff, shoff,
     flags, ehsize, phentsize, phnum, shentsize, shnum,
     shstrndx) = struct.unpack (format, data)
    d = locals().copy()
    del d['data']
    del d['format']
    return d

# Very annoying: the fields are laid out differently.  Why???

#            typedef struct {
#                    Elf32_Word      p_type;
#                    Elf32_Off       p_offset;
#                    Elf32_Addr      p_vaddr;
#                    Elf32_Addr      p_paddr;
#                    Elf32_Size      p_filesz;
#                    Elf32_Size      p_memsz;
#                    Elf32_Word      p_flags;
#                    Elf32_Size      p_align;
#            } Elf32_Phdr;

elf32_phdr = '<LLLLLLLL'

#            typedef struct {
#                    Elf64_Half      p_type;
#                    Elf64_Half      p_flags;
#                    Elf64_Off       p_offset;
#                    Elf64_Addr      p_vaddr;
#                    Elf64_Addr      p_paddr;
#                    Elf64_Size      p_filesz;
#                    Elf64_Size      p_memsz;
#                    Elf64_Size      p_align;
#            } Elf64_Phdr;

elf64_phdr = '<LLQQQQQQ'

def parse_phdr32 (data):
    (type, offset, vaddr, paddr,
     filesz, memsz, flags, align) = struct.unpack (elf32_phdr, data)
    d = locals().copy()
    del d['data']
    return d

# typedef struct {
#    u_int32_t   n_namesz;   /* Length of name. */
#    u_int32_t   n_descsz;   /* Length of descriptor. */
#    u_int32_t   n_type;     /* Type of this note. */
#} Elf_Note;
elf_note = '<LLL'
elf_note_size = struct.calcsize (elf_note)
def parse_note (data):
    return struct.unpack (elf_note, data)

# see sys/procfs.h
#typedef struct prpsinfo {
#    int    pr_version; /* Version number of struct (1) */
#    size_t pr_psinfosz;    /* sizeof(prpsinfo_t) (1) */
#    char   pr_fname[PRFNAMESZ+1];  /* Command name, null terminated (1) */
#    char   pr_psargs[PRARGSZ+1];   /* Arguments, null terminated (1) */
#} prpsinfo_t;
elf_note_psinfo32 = '<LL17s81s'
elf_note_psinfo64 = '<LQ17s81s'
elf_note_psinfo = None
def parse_note_psinfo(core_info, desc):
    def clean_string(x):
        x = x[:x.find('\x00')]
        return x

    version, psinfosz, command, program = struct.unpack_from(
        elf_note_psinfo, desc, 0)

    core_info['program'] = clean_string(program)
    core_info['command'] = clean_string(command)

# see sys/procfs.h
#typedef struct prstatus {
#    int        pr_version; /* Version number of struct (1) */
#    size_t pr_statussz;    /* sizeof(prstatus_t) (1) */
#    size_t pr_gregsetsz;   /* sizeof(gregset_t) (1) */
#    size_t pr_fpregsetsz;  /* sizeof(fpregset_t) (1) */
#    int        pr_osreldate;   /* Kernel version (1) */
#    int        pr_cursig;  /* Current signal (1) */
#    pid_t  pr_pid;     /* Process ID (1) */
#    gregset_t  pr_reg;     /* General purpose registers (1) */
#} prstatus_t;
elf_note_prstatus32 = '<LLLLLLL'
elf_note_prstatus64 = '<LQQQLLL'
elf_note_prstatus = None

def parse_note_prstatus(core_info, desc):
    version, statussz, gregsetsz, fpregsetsz, \
        osreldate, cursig, kernel_thread_id = \
            struct.unpack_from(elf_note_prstatus, desc, 0)

    core_info['signal'] = cursig
    core_info['kernel_thread_id'] = kernel_thread_id
    core_info['osreldate'] = osreldate

def parse_phdr64 (data):
    (type, flags, offset, vaddr,
     paddr, filesz, memsz, align) = struct.unpack (elf64_phdr, data)
    d = locals().copy()
    del d['data']
    return d

#           typedef struct {
#                   Elf32_Word      sh_name;
#                   Elf32_Word      sh_type;
#                   Elf32_Word      sh_flags;
#                   Elf32_Addr      sh_addr;
#                   Elf32_Off       sh_offset;
#                   Elf32_Size      sh_size;
#                   Elf32_Word      sh_link;
#                   Elf32_Word      sh_info;
#                   Elf32_Size      sh_addralign;
#                   Elf32_Size      sh_entsize;
#           } Elf32_Shdr;

elf32_shdr = '<LLLLLLLLLL'

#           typedef struct {
#                   Elf64_Half      sh_name;
#                   Elf64_Half      sh_type;
#                   Elf64_Size      sh_flags;
#                   Elf64_Addr      sh_addr;
#                   Elf64_Off       sh_offset;
#                   Elf64_Size      sh_size;
#                   Elf64_Half      sh_link;
#                   Elf64_Half      sh_info;
#                   Elf64_Size      sh_addralign;
#                   Elf64_Size      sh_entsize;
#           } Elf64_Shdr;

elf64_shdr = '<LLQQQQLLQQ'

def parse_shdr32 (data):
    (name, type, flags, addr, offset,
     size, link, info, addralign, entsize) = struct.unpack (elf32_shdr, data)
    d = locals().copy()
    del d['data']
    return d

def parse_shdr64 (data):
    (name, type, flags, addr, offset,
     size, link, info, addralign, entsize) = struct.unpack (elf64_shdr, data)
    d = locals().copy()
    del d['data']
    return d

#           typedef struct {
#                   Elf32_Word      st_name;
#                   Elf32_Addr      st_value;
#                   Elf32_Size      st_size;
#                   unsigned char   st_info;
#                   unsigned char   st_other;
#                   Elf32_Half      st_shndx;
#           } Elf32_Sym;

elf32_sym = '<LLLBBH'

#           typedef struct {
#                   Elf64_Half      st_name;
#                   unsigned char   st_info;
#                   unsigned char   st_other;
#                   Elf64_Quarter   st_shndx;
#                   Elf64_Addr      st_value;
#                   Elf64_Size      st_size;
#           } Elf64_Sym;

elf64_sym = '<LBBHQQ'

def parse_sym32 (data):
    (name, value, size, info, other, shndx) = struct.unpack (elf32_sym, data)
    d = locals().copy()
    del d['data']
    return d

def parse_sym64 (data):
    (name, info, other, shndx, value, size) = struct.unpack (elf64_sym, data)
    d = locals().copy()
    del d['data']
    return d

def parse_ident (data):
    if data[0:4] != '\177ELF':
        raise ValueError, "not an ELF header"
    else:
        r = {}
        # consider moving these tables out of this function
        r['class'] = {0:'unknown',1:'32-bit',2:'64-bit'}[ord(data[EI_CLASS])]
        r['data']  = {0:'unknown',1:'little-endian',2:'big-endian'}[ord(data[EI_DATA])]
        r['osabi'] = {
            0:'unix', # modern linux reports this as "UNIX - System V"
            1:'hpux', 2:'netbsd', 3:'linux', 4:'hurd', 5:'86open',
            6:'solaris', 7:'monterey', 8:'irix', 9:'freebsd',
            10:'tru64', 97:'arm', 255:'standalone'
            }[ord(data[EI_OSABI])]
        return r

elf_types = {
    0:'unknown', 1:'relocatable', 2:'executable', 3:'shared', 4:'core'
    }

machine_types = {
    0:'unknown', 1:'m32', 2:'sparc', 3:'386', 4:'68k', 5:'88k',
    6:'486', 7:'860', 8:'mips',10:'mips_rs4_be', 11:'sparc64',
    15:'parisc', 20:'ppc', 0x9026:'alpha', 62:'x86_64'
    }

section_types = {
    0:'null',           # inactive
    1:'progbits',       # program defined information
    2:'symtab',         # symbol table section
    3:'strtab',         # string table section
    4:'rela',           # relocation section with addends
    5:'hash',           # symbol hash table section
    6:'dynamic',        # dynamic section
    7:'note',           # note section
    8:'nobits',         # no space section
    9:'rel',            # relocation section - no addends
    10:'shlib',         # reserved - purpose unknown
    11:'dynsym',        # dynamic symbol table section
    12:'num',           # number of section types
    #0x60000000L:'loos', # First of OS specific semantics
    #0x6fffffffL:'hios', # Last of OS specific semantics
    #0x70000000L:'loproc',# reserved range for processor
    #0x7fffffffL:'hiproc',# specific section header types
    #0x80000000L:'louser',# reserved range for application
    #0xffffffffL:'hiuser',# specific indexes
    }

symbol_bindings = {
    # Symbol Binding - ELFNN_ST_BIND - st_info
    0:'local',          # Local symbol
    1:'global',         # Global symbol
    2:'weak',           # like global - lower precedence
    13:'loproc',        # reserved range for processor
    15:'hiproc',        #  specific symbol bindings
    }

symbol_types = {
    # Symbol type - ELFNN_ST_TYPE - st_info
    0:'notype',         # Unspecified type.
    1:'object',         # Data object.
    2:'func',           # Function.
    3:'section',        # Section.
    4:'file',           # Source file.
    6:'tls',            # TLS object.
    #13:'loproc',       # reserved range for processor
    #15:'hiproc',       #  specific symbol types
    }

def getstr (tab, start):
    # fetch a string from a string table, given the start position.
    # strings are zero-terminated.  first and last char of a table
    # are guaranteed to be NUL.
    end = tab.find ('\000', start)
    return tab[start:end]

def go (filename):
    global elf_note_psinfo, elf_note_prstatus

    f = open (filename, 'rb')
    ident = parse_ident (f.read (EI_NIDENT))
    # pick a class
    if ident['class'] == '32-bit':
        elf_ehdr = elf32_ehdr
        elf_phdr = elf32_phdr
        elf_shdr = elf32_shdr
        parse_phdr = parse_phdr32
        parse_shdr = parse_shdr32
        parse_sym  = parse_sym32
        elf_note_prstatus = elf_note_prstatus32
        elf_note_psinfo = elf_note_psinfo32
    elif ident['class'] == '64-bit':
        elf_ehdr = elf64_ehdr
        elf_phdr = elf64_phdr
        elf_shdr = elf64_shdr
        parse_phdr = parse_phdr64
        parse_shdr = parse_shdr64
        parse_sym  = parse_sym64
        elf_note_prstatus = elf_note_prstatus64
        elf_note_psinfo = elf_note_psinfo64
    else:
        raise ValueError, "unknown elf class"

    # ============================================================
    # elf header
    # ============================================================

    nb = struct.calcsize (elf_ehdr)
    d = parse_ehdr (elf_ehdr, f.read (nb))
    d['ident'] = ident
    d['type'] = elf_types.get (d['type'], '%x' % (d['type'],))
    d['machine'] = machine_types.get (d['machine'], '%x' % d['machine'])
    ehdr = d

    if report_out:
        print >>report_out, 'filename: %s' % (filename,)
    ident = ehdr['ident']
    # temporarily remove ident to make the report look nice.
    del ehdr['ident']
    if report_out:
        print >>report_out, 'ELF header:'
        dump_table ([ehdr])
        print >>report_out, 'machine ident:'
        dump_table ([ident])
    ehdr['ident'] = ident
    # ============================================================
    # program headers
    # ============================================================
    phdr_list = []
    f.seek (d['phoff'])
    for i in range (d['phnum']):
        data = f.read (struct.calcsize (elf_phdr))
        p = parse_phdr (data)
        try:
            p['type'] = {
                0:'null', 1:'load', 2:'dynamic',
                3:'interp', 4:'note', 5:'shlib',
                6:'phdr', 7:'tls',
                }[p['type']]
            phdr_list.append (p)
        except KeyError:
            pass

    if report_out:
        print >>report_out, 'program headers:'
        dump_table (phdr_list)

    # ============================================================
    # section headers
    # ============================================================

    shdr_list = []
    strtab_list = []

    f.seek (d['shoff'])
    for i in range (d['shnum']):
        data = f.read (struct.calcsize (elf_shdr))
        s = parse_shdr (data)
        s['type'] = section_types.get (s['type'], '%x' % (s['type'],))
        shdr_list.append (s)
        if s['type'] == 'strtab':
            if i == ehdr['shstrndx']:
                # this section is the string table that contains the names
                # of the sections themselves.  tricky!
                shstrtab_offset, shstrtab_size = s['offset'], s['size']

    # to catch those files with no symbols
    symstrtab = None

    if shdr_list:
        # read section-name string table
        f.seek (shstrtab_offset)
        shstrtab = f.read (shstrtab_size)

        # fill in section names
        for s in shdr_list:
            s['name'] = getstr (shstrtab, s['name'])
            if s['name'] == '.strtab' or s['name'] == '.dynstr':
                # string table for symbols
                symstrtab = s
            elif s['name'] == '.symtab' or s['name'] == '.dynsym':
                # symbol table
                symtab = s

        if report_out:
            print >>report_out, 'section headers:'
            dump_table (shdr_list, left=('name',))


    # ============================================================
    # notes, only useful for core files?
    # ============================================================
    core_info = {}
    for phdr_info in phdr_list:
        if phdr_info['type'] != 'note':
            continue
        f.seek (phdr_info['offset'])
        filesz = phdr_info['filesz']
        data_read = 0

        # Notes are actually an array of notes. I don't know of anywhere
        # that says how many notes there are, just the total length of all
        # notes. So we read notes until we've read enough bytes to have
        # read them all.
        while data_read < filesz:
            data = f.read (elf_note_size)
            namesz, descsz, note_type = parse_note (data)

            name = f.read(namesz)
            desc = f.read(descsz)

            if note_type == 1:
                # Check for FreeBSD branding
                if name == 'FreeBSD\x00' and descsz == 4:
                    pass
                elif name == 'GNU\x00':
                    # doesn't match the struct description
                    pass
                else:
                    parse_note_prstatus(core_info, desc)
            elif note_type == 2:
                # floating point register info
                pass
            elif note_type == 3:
                if name == 'GNU\x00':
                    # doesn't match the struct description
                    pass
                else:
                    parse_note_psinfo(core_info, desc)
            else:
                print "unknown note type:", note_type

            data_read += namesz + descsz + elf_note_size

        if report_out and core_info.has_key('command'):
            print >>report_out, 'Core file notes:'
            print >>report_out, '\tCommand: %(command)s' %(core_info)
            print >>report_out, '\tProgram: %(program)s' %(core_info)
            print >>report_out, '\tSignal: %(signal)s' %(core_info)

    # ============================================================
    # symbols
    # ============================================================

    if not symstrtab:
        syms = []
        if report_out:
            print >>report_out, 'symbols:\n    none'
    else:
        f.seek (symstrtab['offset'])
        sym_names = f.read (symstrtab['size'])
        n_syms = symtab['size'] / symtab['entsize']
        f.seek (symtab['offset'])
        syms = []
        for i in range (n_syms):
            sym = parse_sym (f.read (symtab['entsize']))
            syms.append (sym)
            sym['name'] = getstr (sym_names, sym['name'])
            # replace 'info' with decoded binding & type
            sym['binding'] = symbol_bindings [ sym['info']>>4 ]
            sym_type = sym['info'] & 0xf
            sym['type'] = symbol_types.get (sym_type, '%x' % sym_type)
            del sym['info']

        if report_out:
            if sort:
                syms.sort (lambda a,b: cmp (a[sort], b[sort]))
            print >>report_out, 'symbols:'
            # we'll set these columns manually
            dump_table (syms, ['shndx', 'size', 'value', 'binding', 'type', 'name'], left=('name',))
    return ehdr, phdr_list, shdr_list, syms, core_info

def dump_table (data, columns=None, left=()):
    # <data>: a list of dictionaries.
    # <columns: a list of column headers (need not be complete)
    # <left>: a list of columns you want left-justified.
    if columns is None:
        columns = data[0].keys()
        columns.sort()
    # first pass, find the widest value for each column
    widths = [len(x)+1 for x in columns]
    for i in range (len (data)):
        elem = data[i]
        for j in range (len (columns)):
            key = columns[j]
            val = elem[key]
            if type (val) in (int, long):
                w = len ('%x' % val) + 1
            else:
                w = len ('%s' % val) + 1
            if w > widths[j]:
                widths[j] = w
    # second pass, dump
    for j in range (len (columns)):
        if columns[j] in left:
            report_out.write (' %-*s' % (widths[j], columns[j]))
        else:
            report_out.write (' %*s' % (widths[j], columns[j]))
    report_out.write ('\n')
    for elem in data:
        for j in range (len (columns)):
            key = columns[j]
            val = elem[key]
            if type(val) in (int, long):
                report_out.write (' %*x' % (widths[j], val))
            elif key in left:
                report_out.write (' %-*s' % (widths[j], val))
            else:
                report_out.write (' %*s' % (widths[j], val))
        report_out.write ('\n')

def unittest_main(cb):
    from testhelper import dumb_test_maker
    def _go(out):
        global report_out
        report_out = out
        go('/bin/ls')
    dumb_test_maker(_go)(cb)

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print 'Usage: %s [-sort (name|value)] <filename>' % (sys.argv[0])
    else:
        if '-sort' in sys.argv:
            i = sys.argv.index ('-sort')
            sort = sys.argv[i+1]
            sys.argv.remove ('-sort')
            sys.argv.remove (sort)
        else:
            sort = None
        report_out = sys.stdout
        ehdr, phdr_list, shdr_list, syms, core_info = go (sys.argv[1])
