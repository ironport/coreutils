# -*- Mode: Python -*-

# attempting a version of core utils for random binaries (as opposed to python core dumps)

import os
import parse_elf
import struct
import sys
from pprint import pprint as pp

W = sys.stderr.write

elf_data = {}
# this should be set by the elf data
psize = None

def read_map (filename, base=0):
    global elf_data
    info = parse_elf.go (filename)
    elf_data[filename] = (base, info)
    ehdr, phdrs, shdrs, syms, core_info = info
    result = []
    for phdr in phdrs:
        if phdr['type'] == 'load':
            result.append ((phdr['memsz'], base + phdr['vaddr'], phdr['offset'], phdr['filesz']))
    result.sort()
    return result

class searchable_file:

    block_size = 1<<16

    def __init__ (self, fd, size):
        self.fd = fd
        self.size = size

    def find (self, needle, position, size=None):
        if size is None:
            size = self.size - position
        while position < self.size:
            os.lseek (self.fd, position, 0)
            block = os.read (self.fd, self.block_size)
            maybe = block.find (needle)
            if maybe != -1:
                return position + maybe
            else:
                # fuzz the block size in case needle straddles the boundary
                position += (self.block_size - (len(needle) - 1))
        return None # Not found

    def seek (self, position):
        os.lseek (self.fd, position, 0)

    def read (self, size):
        return os.read (self.fd, size)

def valid_address (addr):
    for mmap, mfd, msize, mfile, base in maps:
        for memsz, vaddr, offset, filesz in mmap:
            if vaddr <= addr < (vaddr + memsz):
                return (addr - vaddr) + offset, mfile
    return None

def to_disk (addr):
    probe = valid_address (addr)
    if probe is None:
        raise ValueError ("address out of range")
    else:
        return probe

def from_disk (pos):
    for mmap, mfd, msize, mfile, base in maps:
        for memsz, vaddr, offset, filesz in mmap:
            if offset <= pos < (offset + filesz):
                return (pos - offset) + vaddr
    raise ValueError, "address out of range"

def read (address, nbytes=4):
    # verify all addresses before trying to read them.
    probe = valid_address (address)
    if probe is not None:
        pos, mm = probe
        mm.seek (pos)
        #print 'addr: %x, pos: %d, mm=%s' % (address, pos, mm)
        return mm.read (nbytes)
    else:
        raise ValueError, "address out of range"

def read_long (address):
    return struct.unpack (long_struct, read (address, psize))[0]

def read_struct (address, format):
    return struct.unpack (format, read (address, struct.calcsize (format)))

def read_string (address):
    if not address:
        return '<null>'
    else:
        r = []
        while 1:
            ch = read (address, 1)
            if ch == '\000':
                break
            else:
                r.append (ch)
                address += 1
        return ''.join (r)

class finder:
    def __init__ (self, s):
        self.last = 0
        self.s = s
    def next (self):
        mmap, mfd, msize, mfile, base = maps[0]
        addr = mfile.find (self.s, self.last)
        if addr is None:
            return None
        else:
            self.last = addr + len (self.s)
            return from_disk (addr)
    def all (self):
        result = []
        while 1:
            try:
                n = self.next()
            except KeyboardInterrupt:
                sys.stderr.write ('\n')
                return result
            else:
                sys.stderr.write ('+')
                if n is None:
                    break
                else:
                    result.append (n)
        sys.stderr.write ('\n')
        return result

def find_all (s):
    "find all occurrences of string <s> in the core file"
    return finder(s).all()

def find (s):
    "find the string <s> in the core file"
    global _f, next
    # save this away so we can continue the search
    _f = finder (s)
    next = _f.next
    return next()

def who_points_to (addr, max_items=30, aligned=True):
    # assumes maps[0] is the core file
    mmap, mfd, msize, mfile, base = maps[0]
    results = []
    # address in string form
    if psize == 4:
        s = struct.pack ('<l', addr)
    else:
        s = struct.pack ('<q', addr)
    found = base
    for i in range (max_items):
        found = mfile.find (s, found + psize)
        sys.stderr.write ('.')
        if found is None:
            break
        else:
            in_mem = from_disk (found)
            if aligned and (in_mem % psize) != 0:
                pass
            else:
                results.append (in_mem)
    sys.stderr.write ('\n')
    return results

def WP (addr=None):
    if addr is None:
        addr = _
    return who_points_to (addr)

symbols = None

def read_symbols():
    global symbols
    r = {}
    for path, (base, (ehdr, phdrs, shdrs, syms, core_info)) in elf_data.items():
        for sym in syms:
            if sym['type'] in ('func', 'object'):
                name = sym['name']
                p = r.get (name, None)
                if p is None:
                    r[name] = p = []
                p.append ((sym['type'], base + sym['value'], path))
    symbols = r

def get_sym (name, address_of=0, which=None):
    probe = symbols.get (name)
    if probe is None:
        return None
    else:
        if which is not None:
            raise NotImplementedError
        kind, val, path = probe[0]
        if kind == 'func' or address_of:
            return val
        else:
            return read_long (val)

# elf_common.h
DT_DEBUG = 21

def find_solibs():
    debug_base = None
    for filename, (base, info) in elf_data.items():
        if filename == exe_path:
            ehdr, phdrs, shdrs, syms, core_info = info
            for d in shdrs:
                if d['type'] == 'dynamic':
                    # ugh, why did I have to undo 64-bit support...
                    #assert (d['entsize'] == 8)
                    #exe_file.seek (d['offset'])
                    offset = d['addr']
                    # Note: 'P' won't work because we may
                    #  not be running on the same machine!
                    if d['entsize'] == 8:
                        spec = '<LL'
                    elif d['entsize'] == 16:
                        spec = '<QQ'
                    for i in range (0, d['size'], d['entsize']):
                        tag, val = read_struct (offset + i, spec)
                        if tag == DT_DEBUG:
                            debug_base = val
    link_map = read_long (debug_base + psize)
    # ok, now we have the link map, we can walk it and find all so's.
    result = []
    # Note: 'P' won't work because we may
    #  not be running on the same machine!
    if psize == 4:
        spec = '<LLLLL'
    elif psize == 8:
        spec = '<QQQQQ'
    while 1:
        addr, name, ld, next, prev = read_struct (link_map, spec)
        result.append ((addr, read_string (name)))
        if not next:
            break
        else:
            link_map = next
    return result

def map_file (path, base=0):
    global maps
    print '%16x %s' % (base, path)
    mmap = read_map (path, base)
    mfd = os.open (path, os.O_RDONLY)
    msize = os.lseek (mfd, 0, 2)
    mfile = searchable_file (mfd, msize)
    maps.append ((mmap, mfd, msize, mfile, base))

def set_psize():
    global psize, long_struct
    # pick a file randomly
    base, info = elf_data[exe_path]
    ehdr, phdrs, shdrs, syms, core_info = info
    ident_class =  ehdr['ident']['class']
    if ident_class == '32-bit':
        psize = 4
        long_struct = '<L'
    elif ident_class == '64-bit':
        psize = 8
        long_struct = '<Q'
    else:
        raise ValueError, "I'm confused"

if __name__=='__main__':

    usage = """\
usage: python %s <exe-file> <core-file>
       python %s -h|--help""" %(sys.argv[0], sys.argv[0])

    if '-h' in sys.argv or '--help' in sys.argv:
        print """\
To use this, do:

%s

If there were any shared libraries, either make sure they are in the same
location from where the binary imported them, or stick them all into the
current directory.
""" %(usage,)
        sys.exit()
    if len(sys.argv) < 3:
        print usage
        sys.exit()

    exe_path = sys.argv[1]
    core_path = sys.argv[2]

    maps = []

    # core file must be first...
    map_file (core_path)
    map_file (exe_path)

    # set the size of a pointer
    set_psize()

    # skip first one, it's the exe, which is already mapped
    solibs = find_solibs()[1:]

    transplant = 0
    for addr, path in solibs:
        if not os.path.isfile (path):
            # try the current directory
            probe = os.path.split(path)[-1]
            if os.path.isfile (probe):
                transplant = 1
                path = probe
            else:
                print 'unable to find %s' % (path,)
                path = None
        if path:
            map_file (path, addr)

    if transplant:
        print '[transplant]'

    read_symbols()

    base, info = elf_data[core_path]
    ehdr, phdrs, shdrs, syms, core_info = info
    command = core_info.get('command')
    death_signal = core_info.get('signal')
    if command:
        print 'Core was generated by "%s"' %(command)
    if death_signal:
        print 'Program terminated with signal %d' %(death_signal)

    # -------------------------------------------------------------------------
    # this eats up about 10MB of memory, which we probably don't need any more.
    # -------------------------------------------------------------------------
    elf_data.clear()

    import code
    banner = """\
Welcome to browse_core.
    """
    code.interact(banner=banner, local=locals())
