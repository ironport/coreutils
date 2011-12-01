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

"""Python core file analysis tool.

core_utils is a module for interacting with a python core file. The same
efficiencies gained by working with python instead of C are realized by using
core_utils instead of gdb. Obviously this statement only applies to python core
files, core_utils doesn't help much if you're exploring a core file that wasn't
created from a python binary.

core_utils works by providing object wrappers around PyObject structures. The
wrappers provide access to meta data about the object, like its address and
reference count and can also usually provide access to the actual value stored
within. For PyStringObject (regular python strings) core_utils can show the
actual string value inside of it. The same holds for ints, longs and floats.
core_utils can inspect the members of a list, tuple and even a dictionary.

The example below takes the python frame pointer (a pointer to a python frame
object) and from that gets the listing of local variables for that frame. Given
those local variables we begin digging around inside of classes to find member
variables and inspect their values.

Once you've mastered the techniques shown here you can debug almost anything :-)

Getting a Python Traceback
==========================

An example might be the best way to see this in action. First we start with
gdb and the first few lines of bt output::

    (gdb) bt
    #0  0x28389e27 in getipnodebyname () from /lib/libc.so.6
    #1  0x28411f98 in sock_recv (s=0x8634ca0, args=0x86ec3cc)
        at /data/home/bvanzant/work/sam-v6-2/third_party/python2.6_6_i386_thr/Modules/socketmodule.c:2313
    #2  0x080d2311 in PyEval_EvalFrameEx (f=0x86b100c, throwflag=0)
        at Python/ceval.c:3679
    #3  0x080d3388 in PyEval_EvalCodeEx (co=0x83fff08, globals=0x4,
        locals=0x8634ca0, args=0x81e002c, argcount=2, kws=0xe8ddf78, kwcount=0,
        defs=0x0, defcount=0, closure=0x0) at Python/ceval.c:2942
    #4  0x080d1510 in PyEval_EvalFrameEx (f=0xe8dde0c, throwflag=0)
        at Python/ceval.c:3774

From there the topmost python frame is the C frame #2 (Being in
PyEval_EvalFrameEx tells us this). From this call we can see that the actual
Python frame object is at 0x86b100c. Let's take that address over to core_utils
and make an object (MO) of it::

    >>> f = MO(0x86b100c)
    >>> print f
    <frame [1] at 0x86b100c>
    >>> help(f.__repr__)
    __repr__(self) method of __main__.frame_object instance
        <type_name [reference count] address>

The repr of f tells us a few things that are fairly common for the objects that
MO returns. The number in [] is the reference count for this object. Reference
counts that are way out of whack (way higher than expected) may be a clue that
something is wrong. The "at" is obviously an address and is the same one we just
passed into MO.

One of the most immediately useful things to get from a frame object is the
python traceback. While gdb can show us where we were in C-land it doesn't tell
us anything about where we were in python. core_utils can tell us though::

    >>> print_traceback(f)
    ('/usr/local/lib/python2.6_6_i386_thr/site-packages/fast_rpc_blocking_threadsafe.py',
    '_read', 84)
    ('/usr/local/lib/python2.6_6_i386_thr/site-packages/fast_rpc_blocking_threadsafe.py',
    'run', 96)
    ('/usr/local/lib/python2.6_6_i386_thr/threading.py', '__bootstrap_inner',
    522)
    ('/usr/local/lib/python2.6_6_i386_thr/threading.py', '__bootstrap', 497)

Inspecting Python Variables
===========================

The frame object from the prior section isn't an actual python frame object. But
we can get most of what we need from this object::

    >>> dir(f)
    ['__doc__', '__getattr__', '__getitem__', '__init__', '__module__',
    '__repr__', 'address', 'locals', 'object_at_offset', 'offsetof',
    'read_slot', 'slots']

    >>> f.print_locals()
    0:       ss: <_socketobject [4] at 0x875bbc4>
    1:   nbytes: <int 14464 [2] at 0x8475a2c>
    2:      res: <str '(J\xd1\x9f\xb1\x00...' (1938 bytes) [1] at 0x9769000>
    3:     res2: <str '(J\xd1\x9f\xb1\x00...' (1938 bytes) [1] at 0xc678000>

From that output we can see that there are a few variables in this frame.
There's a socket object, an integer and two strings. Each of these objects,
being of different types, are inspected in different ways. To get access to any
of these objects we take the index from print_locals() and call local()
Let's look at one of the string objects::

    >>> res = f.local(2)
    >>> res.value()
    '(J\xd1\xe7\x01\x00N ... <truncated>

Unfortunatey socket is a new style python class that uses __slots__ to save
memory. As of this writing I don't know how to find the member _sock that is the
actual C structure containing the socket information (file descriptor, address
family, etc). With this particular core file and this particular C backtrace it
is easy to get the C socket structure, however, this is not necessarily common.

Here's a slightly more advanced example. In this case we start with a tuple::

    >>> t = MO(0x865acac)
    >>> t
    <tuple [[<int 1 [1981] at 0x8231340>, <request_thread [12] at 0x863936c>]]
    (2 items) [1] at 0x865acac>

    >>> t.objects
    [<int 1 [1981] at 0x8231340>, <request_thread [12] at 0x863936c>]

    >>> rt = t.objects[1]

rt now contains the request_thread instance. To get access to the members of
this request_thread instance we call class_members(). class_members() locates
the dictionary (__dict__) for this class instance. New-style python classes that
define __slots__ are not supported by class_members just yet.

    >>> rt.class_members()
    <dict (18 items) [1] at 0x8637824>

    >>> rt.class_members().entries
    [(<str 'job_queue' (9 bytes) [108] (interned) at 0x83934f8>, 141894412),
    <truncated>

And now we're rinsing and repeating. We have a python list of tuples in entries.
Each tuple has two items, both python objects. The first is the key, the second
the value at that key. It just so happens that 'job_queue' is an old style
class, let's see how to open it up::

    >>> jq = MO(141894412)
    >>> jq.in_dict
    <dict (5 items) [1] at 0x875c0b4>

And again, rinse and repeat. Given the dictionary in jq.in_dict we can look at
all of the properites of class job_queue.
::

    >>> jq.in_dict['queue']
    139496812
    >>> q = MO(_)
    >>> q
    <list [<tuple [[<client [570] at 0x863bb8c>, <int 922106 [1] at 0x8474804>
    <truncated>
    >>> len(q)
    358

That job_queue has 358 items in it. We could dig through that big old list there
and inspect each of those items. Or not :-)

Dealing with Threads
====================

These examples should work without threads too. The underlying python structures
don't change with or without threads, its just that the linked list of threads
has length 1 :-).

If you're debugging a threaded python app core_utils can help.
::

    >>> info_threads()
    0 <frame [1] at 0x86b100c>
    1 <frame [1] at 0x975160c>
    2 <frame [1] at 0x9745c0c>

Or to show the traceback for each of those threads::

    >>> ptb_threads(0, 1)
      0 <frame [1] at 0x86b100c>
        ('/usr/local/lib/python2.6_6_i386_thr/site-packages/fast_rpc_blocking_threadsafe.py', '_read', 84)
        ('/usr/local/lib/python2.6_6_i386_thr/site-packages/fast_rpc_blocking_threadsafe.py', 'run', 96)
        ('/usr/local/lib/python2.6_6_i386_thr/threading.py', '__bootstrap_inner', 522)
        ('/usr/local/lib/python2.6_6_i386_thr/threading.py', '__bootstrap', 497)
      1 <frame [1] at 0x975160c>
        ('/usr/local/lib/python2.6_6_i386_thr/site-packages/third_party_utils.py', 'recv_exact', 364)
        ('/usr/local/lib/python2.6_6_i386_thr/site-packages/third_party_utils.py', '_run', 416)
        ('/usr/local/lib/python2.6_6_i386_thr/site-packages/third_party_utils.py', 'run', 401)
        ('/usr/local/lib/python2.6_6_i386_thr/threading.py', '__bootstrap_inner', 522)
        ('/usr/local/lib/python2.6_6_i386_thr/threading.py', '__bootstrap', 497)

To dig in further on a given frame use MO() with the frame address.

Extending core_utils
====================

Put a module named core_utils_local somewhere in your PYTHONPATH and core_utils
will import it for you on startup, loading everything for you to use. This is
similar to a .gdbinit file.

"""

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

# rules for poking around in memory.
# 1) how to find and verify objects in memory.
# Py_OBJECT_HEAD = {refcount, &type}
# Type Objects also have a head, and they point at the 'type' type,
# which we can get the address of as well.

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

def from_disk (pos, addr_map):
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

# ================================================================================
# walking the python pymalloc heap

# these might get tweaked in future
ARENA_SIZE = 256 * 1024
POOL_SIZE = 4 * 1024
POOL_SIZE_MASK = POOL_SIZE - 1
ALIGNMENT_SHIFT = 3
ALIGNMENT = 8
ALIGNMENT_MASK = ALIGNMENT - 1
SMALL_REQUEST_THRESHOLD = 256

# /* Pool for small blocks. */
# struct pool_header {
#       union { block *_padding;
#               uint count; } ref;      /* number of allocated blocks    */
#       block *freeblock;               /* pool's free list head         */
#       struct pool_header *nextpool;   /* next pool of this size class  */
#       struct pool_header *prevpool;   /* previous pool       ""        */
#       uint arenaindex;                /* index into arenas of base adr */
#       uint szidx;                     /* block size class index        */
#       uint nextoffset;                /* bytes to virgin block         */
#       uint maxnextoffset;             /* largest valid nextoffset      */
# };

poolp_struct = 'IPPPIIII'
poolp_size = struct.calcsize (poolp_struct)

def ROUNDUP (x):
    return (x + ALIGNMENT_SHIFT) & ~ALIGNMENT_MASK

POOL_OVERHEAD = ROUNDUP(poolp_size)

def INDEX2SIZE (i):
    return (i + 1) << ALIGNMENT_SHIFT

def NUMBLOCKS (i):
    return (POOL_SIZE - POOL_OVERHEAD) / INDEX2SIZE (i)

def POOL_ADDR (p):
    """Round down an address to the beginning of the pool."""
    return (p & ~POOL_SIZE_MASK)

class pymalloc_pool:

    def __init__(self, addr):
        self.addr = POOL_ADDR(addr)
        self._unpack()

    def _unpack(self):
        bytes = read(self.addr, poolp_size)
        (self.count, self.freeblock, self.next, self.prev,
         self.arenaindex, self.szidx,
         self.nextoffset, self.maxnextoffset
        ) = struct.unpack (poolp_struct, bytes)

    def __repr__(self):
        return '<pymalloc_pool count=%r freeblock=%r arenaindex=%r szidx=%r>' % (
            self.count,
            self.freeblock,
            self.arenaindex,
            self.szidx,
        )

class pymalloc_arena:

    def __init__(self, addr):
        self.object_addr = addr
        self._unpack()

    def _unpack(self):
        arena_struct = 'PPIIPPP'
        arena_object_size = struct.calcsize(arena_struct)
        bytes = read(self.object_addr, arena_object_size)
        (self.address, self.pool_address, self.nfreepools, self.ntotalpools,
         self.freepools, self.nextarena, self.prevarena
        ) = struct.unpack(arena_struct, bytes)

    def __repr__(self):
        return '<pymalloc_arena addr=0x%x pool_addr=0x%x nfreepools=%r ntotalpools=%r' % (
            self.address, self.pool_address, self.nfreepools, self.ntotalpools
        )

def describe_pymalloc():
    num_classes = SMALL_REQUEST_THRESHOLD >> ALIGNMENT_SHIFT
    numpools = [0] * num_classes
    numblocks = [0] * num_classes
    numfreeblocks = [0] * num_classes
    num_free_pools = 0
    maxarenas = get_sym ('maxarenas')
    arenas = get_sym ('arenas')
    print 'maxarenas', maxarenas
    # Visit every arena gathering information.
    for arena_idx in xrange(maxarenas):
        # 28 = sizeof(arena_object) on 32-bit
        addr = arenas + 28*arena_idx
        arena = pymalloc_arena(addr)
        # Address == NULL means it has not been allocated, yet.
        if arena.address:
            base = arena.address
            if base & POOL_SIZE_MASK:
                # Due to alignment, space is lost.  This doesn't seem to happen
                # on our platform.
                base &= ~POOL_SIZE_MASK
                base += POOL_SIZE
            pool_idx = 0
            while base < arena.pool_address:
                pool = pymalloc_pool(base)
                # Check if it is empty.
                if pool.count == 0:
                    num_free_pools += 1
                else:
                    numpools[pool.szidx] += 1
                    numblocks[pool.szidx] += pool.count
                    numfreeblocks[pool.szidx] += (NUMBLOCKS(pool.szidx) - pool.count)
                pool_idx += 1
                base += POOL_SIZE
    print
    headers = ('class', 'size', '#pools', 'used blocks', 'used bytes', 'avail blocks')
    print ('%15s' * len(headers)) % headers
    allocated_bytes = 0
    available_bytes = 0
    pool_header_bytes = 0
    quantization = 0
    for i in range (num_classes):
        size = INDEX2SIZE (i)
        print ('%15s' * len(headers)) % (
            i, size, numpools[i], numblocks[i], numblocks[i] * size, numfreeblocks[i]
            )
        allocated_bytes += numblocks[i] * size
        available_bytes += numfreeblocks[i] * size
        pool_header_bytes += numpools[i] * POOL_OVERHEAD
        quantization += numpools[i] * ((POOL_SIZE - POOL_OVERHEAD) % size)
    print '%12d bytes in allocated blocks' % allocated_bytes
    print '%12d bytes in available blocks' % available_bytes
    print '%12d bytes lost to pool headers' % pool_header_bytes
    print '%12d bytes in %d unused pools' % (num_free_pools * POOL_SIZE, num_free_pools)

def _block_is_free(pool, bp):
    p = pool.freeblock
    while p:
        if p == bp:
            return 1
        p = read_long(p)
    return 0

def pymalloc_walk_heap (idx, callback, limit=100, pool_offset=0):
    """Walk the Python malloc heap and call `callback` for every allocated
    piece of membery.

    `callback` should be a function that takes two arguments.  The first is the
    address of the allocation.  The second is the size of the allocation.
    Beware that pointers for garbage-collected objects point to the gc header,
    not the object header.
    """
    maxarenas = get_sym ('maxarenas')
    arenas = get_sym ('arenas')
    every = maxarenas/10

    for arena_idx in xrange(maxarenas):
        addr = arenas + 4*arena_idx
        arena = pymalloc_arena(addr)
        if arena.address:
            base = arena.address
            if base & POOL_SIZE_MASK:
                # Due to alignment, space is lost.  This doesn't seem to happen
                # on our platform.
                base &= ~POOL_SIZE_MASK
                base += POOL_SIZE
            pool_idx = 0
            while base < arena.pool_address:
                pool = pymalloc_pool(base)
                # Check if it is empty.
                if pool.count != 0 and pool.szidx == idx:
                    size = INDEX2SIZE(pool.szidx)
                    bp = pool.addr + POOL_OVERHEAD
                    for block_idx in xrange(NUMBLOCKS(pool.szidx)):
                        if limit:
                            if not _block_is_free(pool, bp):
                                callback (bp, size)
                                limit -= 1
                        else:
                            return
                        bp += size
                pool_idx += 1
                base += POOL_SIZE
        # progress dot
        if every and not ((i+1) % every):
            sys.stderr.write ('.')

# ================================================================================
# walking the freebsd malloc heap

#/*
# * This structure describes a page worth of chunks.
# */

#struct pginfo {
#    struct pginfo       *next;  /* next on the free list */
#    void                *page;  /* Pointer to the page */
#    u_short             size;   /* size of this page's chunks */
#    u_short             shift;  /* How far to shift for this size chunks */
#    u_short             free;   /* How many free chunks */
#    u_short             total;  /* How many chunk */
#    u_int               bits[1]; /* Which chunks are free */
#};

#/* Pointer to page directory. Allocated "as if with" malloc */
#static struct   pginfo **page_dir;

#/*
# * This structure describes a number of free pages.
# */

#struct pgfree {
#    struct pgfree       *next;  /* next run of free pages */
#    struct pgfree       *prev;  /* prev run of free pages */
#    void                *page;  /* pointer to free pages */
#    void                *end;   /* pointer to end of free pages */
#    size_t              size;   /* number of bytes free */
#};
#/* Free pages line up here */
#static struct pgfree free_list;

page_table_origin = None

malloc_pageshift = 15
malloc_minsize = 16
malloc_pagesize = 1L << malloc_pageshift
malloc_pagemask = malloc_pagesize - 1

sizeof_pginfo = struct.calcsize ('=llHHHH')

#    struct pginfo       *next;  /* next on the free list */
#    void                *page;  /* Pointer to the page */
#    u_short             size;   /* size of this page's chunks */
#    u_short             shift;  /* How far to shift for this size chunks */
#    u_short             free;   /* How many free chunks */
#    u_short             total;  /* How many chunk */
#    u_int               bits[1]; /* Which chunks are free */

MALLOC_NOT_MINE = 0
MALLOC_FREE = 1
MALLOC_FIRST = 2
MALLOC_FOLLOW = 3
MALLOC_MAGIC = 4

MALLOC_MAGICS = ['not_mine', 'free', 'first', 'follow']

W = sys.stderr.write

# two kinds of allocation - 'page' and 'chunk'
# if page_dir[index] == MALLOC_FIRST => 'page allocation'
#                    >= MALLOC_MAGIC => 'chunk allocation'

def collect_alloc_stats():
    page_dir = get_sym ('page_dir')
    ninfo = get_sym ('malloc_ninfo')
    run_start = 0
    run_n = 0
    # Counts of each page type (4 types)
    chunk_pages = 0
    not_mine_pages = 0
    block_pages = 0
    free_pages = 0

    runs = []
    hist = {}
    i = 0
    while i < ninfo:
        maybe_magic = read_long (page_dir)
        if maybe_magic < MALLOC_MAGIC:
            if maybe_magic == MALLOC_FREE:
                # this page is free
                free_pages += 1
            elif maybe_magic == MALLOC_FIRST:
                # first of a multi-page run
                run_start = i
                run_n = 1
                while i < ninfo:
                    i += 1
                    page_dir += 4
                    maybe_magic = read_long (page_dir)
                    if maybe_magic==MALLOC_FOLLOW:
                        run_n += 1
                    else:
                        runs.append ((run_start, run_n))
                        break
                block_pages += run_n
                continue
            elif maybe_magic == MALLOC_FOLLOW:
                raise 'Floating follow?'
            elif maybe_magic == MALLOC_NOT_MINE:
                not_mine_pages += 1
            else:
                raise "Huh?"
        else:
            next, page, size, shift, free, total = read_struct (maybe_magic, '=llHHHH')
            chunk_total, chunk_free = hist.get (size, (0, 0))
            hist[size] = (chunk_total + total, chunk_free + free)
            chunk_pages += 1
        page_dir += 4
        i += 1
        if i % (ninfo/10) == 0:
            sys.stderr.write ('.')
    print
    print 'Found %i chunk_pages' % chunk_pages
    print 'Found %i free_pages' % free_pages
    print 'Found %i block_pages' % block_pages
    print 'Found %i not_mine_pages' % not_mine_pages
    return hist, runs, ninfo, free_pages

def num_allocated_arenas():
    total = 0
    maxarenas = get_sym ('maxarenas')
    arenas = get_sym ('arenas')
    for arena_idx in xrange(maxarenas):
        addr = arenas + 4*arena_idx
        arena = pymalloc_arena(addr)
        if arena.address:
            total += 1
    return total

def describe_heap():
    """Print information about the malloc heap.

    This will print a summary of the malloc heap.  You'll need to read and
    study the malloc implementation to understand how it uses buckets and
    pages to understand this output.
    """
    hist, runs, ninfo, nfree = collect_alloc_stats()
    narenas = num_allocated_arenas()
    hi = hist.items()
    hi.sort()
    sum_btotal = 0
    sum_bfree  = 0
    for size, (total, free) in hi:
        print 'size: %5d total:%8d free:%8d bused:%9d btotal:%9d bfree:%9d' % (
            size, total, free, (total-free) * size, total * size, free * size
            )
        sum_btotal += total * size
        sum_bfree += free * size
    run_d = {}
    for (run_start, run_n) in runs:
        n = run_d.get (run_n, 0)
        run_d[run_n] = n + 1
    probably_pymalloc = run_d[8]
    run_d = run_d.items()
    run_d.sort()
    print 'page allocations:'
    print 'npages        KB   count'
    sum_ptotal = 0
    sum_pages = 0
    for (size, count) in run_d:
        print '%3d   %10d   %5d' % (
            size,
            (size * malloc_pagesize) / 1024,
            count
            )
        sum_ptotal += (size * malloc_pagesize) * count
        sum_pages += (count * size)
    print '--- chunked data ---'
    print 'bytes_total: %10d' % sum_btotal
    print 'bytes_free : %10d' % sum_bfree
    print '--- page allocations ---'
    print 'bytes_total: %10d' % sum_ptotal
    print 'pages_total: %10d' % sum_pages
    print '--- page allocations (excluding pymalloc) ---'
    print 'bytes_total: %10d' % (sum_ptotal - (narenas * 256 * 1024))
    print 'pages_total: %10d' % (sum_pages - (narenas * 8))
    print '--- all pages ---'
    print 'total pages:%d free:%d' % (ninfo, nfree)
    print 'bytes_total: %10d' % (ninfo * malloc_pagesize)
    print 'bytes_free : %10d' % (nfree * malloc_pagesize)
    # here we should walk the free list and see if the numbers match.

def ptr2index (address):
    return (address >> malloc_pageshift) - page_table_origin

def index2ptr (index):
    return (index + page_table_origin) << malloc_pageshift

def pageround (address):
    return address - (address & malloc_pagemask)

def print_bits (ints):
    l = [None] * (len(ints) * 32)
    i = 0
    for n in ints:
        for x in range (32):
            l[i] = n & 1
            n >>= 1
            i += 1
    return ''.join (map (str, l))

def describe_pointer (address=None):
    if address is None:
        address = _
    if is_pymalloc_pointer(address):
        print 'malloc:'
        describe_malloc_pointer(address)
        print 'pymalloc:'
        describe_pymalloc_pointer(address)
    else:
        describe_malloc_pointer(address)

def describe_malloc_pointer (address):
    index = ptr2index (address)
    page_dir = get_sym ('page_dir')
    page_entry = page_dir + (4 * index)
    maybe_magic = read_long (page_entry)
    if maybe_magic > MALLOC_MAGIC:
        next, page, size, shift, free, total = read_struct (maybe_magic, '=llHHHH')
        # how many ints in the bitmap? (no I don't understand this calculation)
        n_ints = ((malloc_pagesize >> shift)+31) / 32
        ints = read_struct (maybe_magic + sizeof_pginfo, '=' + ('l' * n_ints))
        bits = print_bits (ints)[:total]
        which = (address & malloc_pagemask) / size
        front = page + (which * size)
        print 'size:%d shift:%d page:0x%x address:0x%x total:%d free:%d' % (
            size,
            shift,
            page,
            address,
            total,
            free
            )
        print 'bitmap %r' % (bits)
        print 'front:0x%x index:%d free?:%s internal?:%d' % (
            front,
            which,
            bits[which],
            front != address
            )
    else:
        print 'page-alloc: page=0x%x status=%s' % (
            address >> malloc_pageshift,
            MALLOC_MAGICS[maybe_magic]
            )

def _pymalloc_address_in_range(p, pool):
    arenas = get_sym ('arenas')
    maxarenas = get_sym ('maxarenas')
    try:
        arena = pymalloc_arena(arenas + 4*pool.arenaindex)
    except ValueError:
        return False
    return pool.arenaindex < maxarenas and (p - arena.address) < ARENA_SIZE and arena.address != 0

def is_pymalloc_pointer(p):
    try:
        pool = pymalloc_pool(p)
    except ValueError:
        return False
    return _pymalloc_address_in_range(p, pool)

def describe_pymalloc_pointer (p=None):
    if p is None:
        p = _
    pool = pymalloc_pool(p)
    if not _pymalloc_address_in_range(p, pool):
        raise AssertionError('Address was not allocated by pymalloc.')
    size = INDEX2SIZE (pool.szidx)
    n, offset = divmod ((p - (pool.addr + poolp_size)), size)
    front = (n * size) + pool.addr + poolp_size
    print 'addr:0x%x front:0x%x pool:0x%x count=%d/%d arenaindex=%d szidx=%d [%d bytes]' % (
        p, front, pool.addr, pool.count, NUMBLOCKS (pool.szidx), pool.arenaindex, pool.szidx, size
        )

DPP = describe_pymalloc_pointer

def front(p):
    if is_pymalloc_pointer(p):
        pool = pymalloc_pool(p)
        size = INDEX2SIZE (pool.szidx)
        n, offset = divmod ((p - (pool.addr + poolp_size)), size)
        return (n * size) + pool.addr + poolp_size
    else:
        index = ptr2index (p)
        page_dir = get_sym ('page_dir')
        page_entry = page_dir + (4 * index)
        maybe_magic = read_long (page_entry)
        if maybe_magic > MALLOC_MAGIC:
            next, page, size, shift, free, total = read_struct (maybe_magic, '=llHHHH')
            # how many ints in the bitmap? (no I don't understand this calculation)
            n_ints = ((malloc_pagesize >> shift)+31) / 32
            ints = read_struct (maybe_magic + sizeof_pginfo, '=' + ('l' * n_ints))
            bits = print_bits (ints)[:total]
            which = (p & malloc_pagemask) / size
            return page + (which * size)
        elif maybe_magic == MALLOC_FOLLOW:
            return front(p-malloc_pagesize)
        elif maybe_magic == MALLOC_FIRST:
            return (p >> malloc_pageshift) << malloc_pageshift
        elif maybe_magic == MALLOC_NOT_MINE:
            raise ValueError('Address not allocated by malloc.')
        elif maybe_magic == MALLOC_FREE:
            raise ValueError('Page freed.')
        else:
            raise ValueError('Unknown magic %r.' % (maybe_magic,))

def find_recent_page_chunks (search_size, n=5, offset=10):
    # search the most recently-allocated pages for chunk size <size>
    # and return their addresses
    first_page_dir = get_sym ('page_dir')
    ninfo = get_sym ('malloc_ninfo')
    result = []
    for i in range (ninfo-(1+offset), 1, -1):
        page_dir = first_page_dir + (4 * i)
        maybe_magic = read_long (page_dir)
        if maybe_magic > MALLOC_MAGIC:
            next, page, size, shift, free, total = read_struct (maybe_magic, '=llHHHH')
            if size == search_size:
                result.append ((maybe_magic, next, page, size, shift, free, total))
                n -= 1
                if not n:
                    return result

def explore_page (address, size):
    for i in range (malloc_pagesize / size):
        try:
            print make_object (address + (size * i))
        except:
            print repr(read (address + (size * i), size))

def dump_free_list():
    free_list = get_sym ('free_list')
    sum = 0L
    while free_list:
        free_list, prev, page, end, size = read_struct (free_list, '=lllll')
        #sys.stderr.write ('[%x %d]' % (page, size))
        s = str(size/(4096 * 8))
        if len(s) == 1:
            sys.stderr.write (s)
        else:
            sys.stderr.write ('[%s]' % s)
        sum += size
    sys.stderr.write ('\ntotal free: %r\n' % sum)

def walk_pages (file=sys.stderr):
    page_dir = get_sym ('page_dir')
    ninfo = get_sym ('malloc_ninfo')
    nfree = 0
    run_start = 0
    run_n = 0
    ninfo_i = 0
    import array
    page_dir = array.array ('l', read (page_dir, 4 * ninfo))
    # space in chunks up to ninfo
    chunks = [None] * ninfo
    chunk_i = 0
    # first pass, read page data
    while ninfo_i < ninfo:
        maybe_magic = page_dir[ninfo_i]
        if maybe_magic < MALLOC_MAGIC:
            if maybe_magic == MALLOC_FREE:
                file.write ('0')
                # this page is free
            elif maybe_magic == MALLOC_FIRST:
                file.write ('[')
                # first of a multi-page run
                run_start = ninfo_i
                run_n = 1
                while ninfo_i < ninfo:
                    ninfo_i += 1
                    maybe_magic = page_dir[ninfo_i]
                    if maybe_magic==MALLOC_FOLLOW:
                        #file.write ('1')
                        run_n += 1
                    else:
                        file.write ('%d]' % run_n)
                        break
                continue
            elif maybe_magic == MALLOC_FOLLOW:
                # follow-on in a multi-page run
                raise 'Floating follow?'
            elif maybe_magic == MALLOC_NOT_MINE:
                file.write ('?')
            else:
                raise "Huh?"
        else:
            file.write ('-')
        ninfo_i += 1

BITS = [ 1L << i for i in range (32) ]

def walk_heap (callback):
    """Walk the FreeBSD malloc heap, and call `callback` for every allocated
    piece of memory.

    `callback` should be a function that takes 3 arguments.  The first argument
    is the type of allocation ('page' or 'chunk').  The second is the size of
    the allocation (not the size the user requested, the aligned size in
    malloc).  The third is the address of the allocation.
    """
    page_dir = get_sym ('page_dir')
    ninfo = get_sym ('malloc_ninfo')
    origo = get_sym ('malloc_origo')
    nfree = 0
    run_start = 0
    run_n = 0
    ninfo_i = 0

    import array
    page_dir = array.array ('L', read (page_dir, 4 * ninfo))
    # space in chunks up to ninfo
    chunks = [None] * ninfo
    chunk_i = 0

    # first pass, read page data

    while ninfo_i < ninfo:
        maybe_magic = page_dir[ninfo_i]
        if maybe_magic < MALLOC_MAGIC:
            if maybe_magic == MALLOC_FREE:
                # this page is free
                nfree += 1
            elif maybe_magic == MALLOC_FIRST:
                # first of a multi-page run
                run_start = ninfo_i
                run_n = 1
                while ninfo_i < ninfo:
                    ninfo_i += 1
                    maybe_magic = page_dir[ninfo_i]
                    if maybe_magic==MALLOC_FOLLOW:
                        run_n += 1
                    else:
                        size = run_n << malloc_pageshift
                        address = (run_start+origo) << malloc_pageshift
                        callback ('page', size, address)
                        break
                continue
            elif maybe_magic == MALLOC_FOLLOW:
                # follow-on in a multi-page run
                raise 'Floating follow?'
            elif maybe_magic == MALLOC_NOT_MINE:
                pass
            else:
                raise "Huh?"
        else:
            chunks[chunk_i] = maybe_magic
            chunk_i += 1
        if ninfo_i % (ninfo/10) == 0:
            sys.stderr.write ('.')
        ninfo_i += 1

    # second pass, sort and read chunks

    chunks = chunks[:chunk_i]
    chunks.sort()
    n_chunks = len(chunks)

    sys.stderr.write ('\n')

    for j in xrange (n_chunks):
        chunk = chunks[j]
        next, page, size, shift, free, total = read_struct (chunk, '=LLHHHH')
        n_ints = ((malloc_pagesize >> shift)+31) / 32
        ints = read_struct (chunk + sizeof_pginfo, '=' + ('l' * n_ints))
        #callback ('chunk-page', (page, size, shift, total, print_bits (ints)[:total]))
        i = 0
        for n in ints:
            for bit in BITS:
                # n & 1 == 'free'
                if not (n & bit):
                    callback ('chunk', size, page + (size * i))
                i += 1
                if i >= total:
                    break
        if j % (n_chunks/10) == 0:
            sys.stderr.write ('*')

    sys.stderr.write ('\n')

# sample callback that prints the address of all page allocations
def big_cb (kind, size, addr):
    if kind == 'page':
        print '[0x%0x %d]' % (addr, size)

# ================================================================================

def get_refcount (address):
    return read_long (address)

def is_type_object (address):
    if all_type_objects.has_key (address):
        return True
    else:
        try:
            return read_long (address + 4) == type_addr
        except ValueError:
            return False

def is_object (address):
    return is_type_object (read_long (address + psize))

class finder:
    def __init__ (self, s):
        self.last = 0
        self.s = s
    def next (self):
        addr = core_file.find (self.s, self.last)
        if addr is None:
            return None
        else:
            self.last = addr + len (self.s)
            return from_disk (addr, heap)
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
    # biggest segment should be the heap
    memsz, vaddr, offset, filesz = heap[-1]
    results = []
    # address in string form
    s = struct.pack ('<l', addr)
    # start at front of heap
    found = offset
    for i in xrange (max_items):
        found = core_file.find (s, found + 4)
        sys.stderr.write ('.')
        if found is None:
            break
        else:
            in_mem = from_disk (found, heap)
            if aligned:
                if (in_mem % 4) == 0:
                    results.append (in_mem)
            else:
                results.append (in_mem)
    sys.stderr.write ('\n')
    return results

def WP (addr=None):
    if addr is None:
        addr = _
    return who_points_to (addr)

_obj_dict = {}
def _get_obj_callback(type, size, address):
    try:
        if is_object(address):
            name = type_name (address)
            _obj_dict[name] = _obj_dict.get(name, 0) + 1
    except ValueError:
        pass

def get_object_counts():
    """get_object_counts() -> dict
    Returns the number of times each object is found.
    Result: <key> - name of object <value> - number of times found
    """
    walk_heap(_get_obj_callback)
    return _obj_dict

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

def frame_ptr_from_tstate_ptr(tstate_ptr):
    """Given a PyThreadState* get the address of the frame pointer."""
    return read_long(tstate_ptr + (2 * psize))

def info_threads(start_thread_num=0, end_thread_num=sys.maxint, show_traceback=False):
    """Print out all of the current python threads.
    Use start_thread_num and end_thread_num to limit the threads shown to a
    range (inclusive)
    """

    # There may be a bunch of Python interpreters running, this code only
    # operates on the first one. It could easily be extended.
    # Inside of a given interpreter there may be many threads running.
    # This looks at each of the threads and grabs the thread state. Within
    # the thread state we can find the current frame for this thread.
    # Because the structures involved here are, at least at the beginning,
    # composed of pointers the pointer arithemetic is done by hand rather than
    # using the struct module.

    # The interpreter struct (PyInterpreterState) has the next interpreter
    # pointer as its first entry. It has the first thread state pointer
    # as its next entry.
    # The thread state struct (PyThreadState) has the next thread state pointer
    # as its first entry. The second entry is a pointer to the
    # PyInterpreterState and the third entry is a pointer to the stack frame.

    interp = get_sym('interp_head')
    ts = read_long(interp + psize)
    thread_num = 0
    while ts != 0:
        if thread_num >= start_thread_num and thread_num <= end_thread_num:
            frame_ptr = frame_ptr_from_tstate_ptr(ts)
            frame = make_object(frame_ptr)
            print "%3d %r" %(thread_num, frame)
            if show_traceback:
                print_traceback(frame, indent_level=4)

        ts = read_long(ts)
        thread_num += 1

def ptb_threads(start_thread_num=0, end_thread_num=sys.maxint):
    """Show a traceback for each thread. Similar to `thread apply bt all` or
    `thread apply start-end bt` in gdb."""
    info_threads(start_thread_num=start_thread_num,
        end_thread_num=end_thread_num, show_traceback=True)

def get_current_frame():
    ts = get_sym ('_PyThreadState_Current')
    if ts == 0:
        print "No python threads currently holding the GIL"
        print "Try list_threads() or info_threads() to find all of the known threads"
        return None

    frame_ptr = frame_ptr_from_tstate_ptr(ts)
    return make_object (frame)

def print_current_traceback():
    print_traceback (
        get_current_frame()
        )

PTB = print_current_traceback

def get_sysdict():
    """get_sysdict() -> core_dict_object of the sys module
    """
    ts = get_sym ('_PyThreadState_Current')
    interp = read_long (ts + 4)
    sysdict = read_long (interp + 12)
    return make_object (sysdict)

#
# Find a global variable
# ex: find the value of concurrency in __main__
#   get_module_global('__main__', 'concurrency')
#
def get_module_global (modname, globalname):
    sd = get_sysdict()
    modules = MO (sd['modules'])
    mod = MO (modules[modname])
    var = MO (mod.dict[globalname])
    return var

def print_traceback(frame, indent_level=0):
    """print_traceback(frame) -> None
    Prints a traceback from the given frame to stdout.
    """
    for x in get_traceback(frame):
        print " "*indent_level + str(x)

all_objects = {}

NULL = 'NULL'

all_objects[0L] = NULL
all_objects[0] = NULL

class NotAnObject (Exception):
    pass

# recursive data structures are troublesome.
# maybe a 'proxy' type could be stuck here that
# would produce the desired object at a later time?

def make_object (address):
    if all_objects.has_key (address):
        return all_objects[address]
    elif is_object (address):
        typo = read_long (address + psize)
        name = read_string (read_long (typo + type_name_offset))
        kind = lookup_object_type (name)
        if kind:
            result = kind (address)
        else:
            result = object (address)
        all_objects[address] = result
        return result
    else:
        raise NotAnObject

def lookup_object_type (name):
    kind = globals().get ('%s_object' % name, None)
    if kind is None:
        # ugh, special cases...
        if name == 'instance method':
            return instance_method_object
        else:
            return None
    else:
        return kind

class object:

    def __init__ (self, address):
        self.address = address

    def object_at_offset (self, offset):
        return make_object (read_long (self.address + offset))

    def read_slot (self, name):
        """Reads a named slot. The slot must be present in self.slots."""
        isobj, offset = self.slots.get (name, (None, None))
        if offset is None:
            raise ValueError('Not a valid slot name')
        return read_long (self.address + offset)

    def offsetof (self, name):
        return self.slots[name][1]

    def __getattr__ (self, name):
        isobj, offset = self.slots.get (name, (None, None))
        if isobj is not None:
            if isobj:
                try:
                    return self.object_at_offset (offset)
                except NotAnObject:
                    return read_long (self.address + offset)
            else:
                return read_long (self.address + offset)
        else:
            raise AttributeError

    def class_members(self):
        """This is incomplete. Doesn't work if the class has __slots__.
        Loosely based on _PyObject_GetDictPtr"""

        dictoffset = self.ob_type.tp_dictoffset

        if dictoffset > 0:
            return self.object_at_offset(8)

        if hasattr(self, 'in_dict'):
            return self.in_dict

        if dictoffset == 0:
            print 'tp_dictoffset is 0, no __dict__?'

        if dictoffset < 0:
            # Most likely this class is using __slots__ to define its members
            # and doesn't have a regular dictionary for storing them.
            raise NotImplementedError('Class dictionary stored in unsupported way?')

    def __repr__ (self):
        """<type_name [reference count] address>"""
        return '<%s [%d] at 0x%x>' % (
            read_string (self.ob_type.read_slot ('tp_name')),
            self.ob_refcnt,
            self.address
            )

class tuple_object (object):

    def __repr__ (self):
        llen = self.ob_size
        self.objects = []
        for i in xrange (llen):
            self.objects.append (
                make_object (
                    read_long (
                        self.address
                        + self.offsetof ('ob_item')
                        + i * psize
                        )
                    )
                )
        return '<tuple [%s] (%d items) [%d] at 0x%x>' % (
            repr (self.objects),
            llen,
            self.ob_refcnt,
            self.address
            )

    def __getitem__(self, index):
        return make_object (
            read_long (
                self.address
                + self.offsetof('ob_item')
                + index * psize
                )
            )

    def __len__(self):
        return self.ob_size

class list_object (object):

    def __len__ (self):
        return self.ob_size

    def __getitem__ (self, index):
        assert (is_object (self.address))
        assert (type_name (self.address) == 'list')
        llen = read_long (self.address + 8)
        items = read_long (self.address + 12)
        oaddr = items + (index * 4)
        return make_object (read_long (oaddr))

    def __getitem__ (self, index):
        array = self.read_slot ('ob_item')
        return make_object (read_long (array + (index * psize)))

    def __repr__ (self):
        """<list [list entries] (len(list) items) [reference count] at address>"""
        try:
            reprs = []
            for i in range (len (self)):
                reprs.append (repr (self[i]))
            reprs = ', '.join (reprs)
        except:
            reprs = '<error printing list>'
        return '<list [%s] (%d items) [%d] at 0x%x>' % (
            reprs,
            self.ob_size,
            self.ob_refcnt,
            self.address
            )

class int_object (object):
    def __repr__ (self):
        """<int integer value [reference count] at address>"""
        return '<int %d [%d] at 0x%x>' % (self.ob_ival, self.ob_refcnt, self.address)

class long_object (object):

    def __init__ (self, address):
        object.__init__ (self, address)
        self.value = self.decode()

    def __repr__ (self):
        """<long integer value [reference count] at address>"""
        return '<long %r [%d] at 0x%x>' % (
            self.value,
            self.ob_refcnt,
            self.address
            )

    def decode (self):
        SHIFT = 15
        ob_size = self.ob_size
        neg = 0
        if ob_size < 0:
            ob_size = -ob_size
            neg = 1
        n = 0L
        digit_offset = self.offsetof ('ob_digit')
        for i in xrange (ob_size-1, -1, -1):
            n <<= SHIFT
            n |= struct.unpack (
                '<h',
                read (self.address + digit_offset + (i*2), 2)
                )[0]
        if neg:
            return - n
        else:
            return n

class float_object (object):
    def __repr__ (self):
        """<float float value [reference count] at address>"""
        return '<float %r [%d] at 0x%x>' % (
            self.value(), self.ob_refcnt, self.address
            )
    def value (self):
        return read_struct (
            self.address + self.offsetof ('ob_fval'), 'd'
            )[0]

class type_object (object):

    def __repr__ (self):
        """<type type name [reference count] at address>"""
        return '<type "%s" [%d] at 0x%x>' % (
            read_string (self.read_slot ('tp_name')),
            self.ob_refcnt,
            self.address
            )

max_str_len = 25
class str_object (object):

    def __repr__ (self):
        """<str str_val (len(str) bytes) [reference count] at address>"""
        if self.ob_size < max_str_len:
            sval = self.value()
        else:
            sval = read (
                self.address + self.offsetof ('ob_sval'), max_str_len
                ) + '...'
        if self.ob_sstate:
            interned = ' (interned)'
        else:
            interned = ''
        return '<str %r (%d bytes) [%d]%s at 0x%x>' % (
            sval,
            self.ob_size,
            self.ob_refcnt,
            interned,
            self.address
            )

    def __len__ (self):
        return self.ob_size

    def value (self):
        return read (
            self.address + self.offsetof ('ob_sval'),
            self.ob_size
            )

# dict
# 0:ob_refcnt, 4:ob_type, 8:ma_fill, 12:ma_used, 16:ma_size, 20:ma_poly, 24:ma_table, 28:ma_lookup
# entry
# 0:me_hash, 4:me_key, 8:me_value, [aligner]

class dict_object (object):

    def __init__ (self, address):
        object.__init__ (self, address)
        address = self.address
        ma_mask = self.ma_mask
        ma_table = read_long (self.address + self.offsetof ('ma_table'))
        ma_size = ma_mask + 1
        self.entries = []
        for i in range (ma_size):
            # XXX 64-bit: padding?
            entry = ma_table + ((3 * psize) * i)
            key = read_long (entry + psize)
            val = read_long (entry + (2 * psize))
            if val:
                #self.entries.append ((make_object (key), make_object (val)))
                self.entries.append ((make_object (key), val))

    def __repr__ (self):
        """<dict (len(dict)) [reference count] at address>"""
        return '<dict (%d items) [%d] at 0x%x>' % (
            len (self.entries),
            self.ob_refcnt,
            self.address
            )

    def __getitem__ (self, key):
        for k, v in self.entries:
            if type(key) == type ('') and isinstance (k, str_object):
                if k.value() == key:
                    return v
            elif k.address == key.address:
                return v
        raise KeyError, key

class module_object (object):

    def __init__ (self, address):
        object.__init__ (self, address)
        # watch out for the __getattr__ below!
        self.dict = object.__getattr__ (self, 'md_dict')

    def __getattr__ (self, key):
        return self.dict[key]

    def __repr__ (self):
        """<module name at address>"""
        name = make_object(self.__name__).value()
        return '<module %r at 0x%x>' % (name, self.address)

class frame_object (object):

    def __getitem__ (self, i):
        """Deprecated in favor of local()."""
        raise NotImplementedError()

    def get_var(self, name):
        """Return the local variable with name "name"."""

    def get_local_names(self):
        names = []
        for i in range(self.nlocals):
            names.append(self.f_code.co_varnames[i].value())
        return names

    def local(self, i):
        """Return the local variable at index i."""
        zero = self.address + self.offsetof ('f_localsplus')
        return make_object (read_long (zero + (i*psize)))

    @property
    def nlocals(self):
        """The number of local variables in this frame."""
        return self.f_code.co_nlocals + len(self.f_code.co_cellvars) + len(self.f_code.co_freevars)

    def locals(self):
        """Return a dictionary of the local variables in this frame.

        Since this returns an instance of every variable in the local frame
        it's possible that this might take a ton of memory. print_values()
        will operate in constant memory.
        """
        locals_dict = {}
        names = self.get_local_names()
        for i in range(self.nlocals):
            locals_dict[names[i]] = self.local(i)

        return locals_dict

    def print_locals(self):
        """Print out the local variables from the given frame.

        The output is:

        variable_index: variable_name: repr(var)

        To inspect any of these variables further use
        <frame>.local(variable_index) to get reference to that variable.

        Use <frame>.locals() to get a dictionary of the locals instead of a
        printout.
        """
        names = self.get_local_names()
        for i in range(self.nlocals):
            print "%d: %8s: %s" %(i, names[i], self.local(i))

    def up(self):
        """Returns the next frame or None."""
        if self.f_back is NULL:
            return None
        return self.f_back

    def print_traceback(self):
        """Print the traceback leading up to this frame."""
        print_traceback(self)


# For the lazy, to get the offset with C:
####include "Python.h"
####include "compile.h"
####include "frameobject.h"
####include <stdio.h>
####include <stddef.h>
###
###main()
###{
###printf("%i\n",offsetof(PyFrameObject,f_referers));
###}
#
# using gdb:
# first, define the following macro:
# define offset
#   print (int)&((($arg0 *)0)->$arg1)
# end
# then, use it like this:
# (gdb) offset PyFrameObject f_nlocals
# $1 = 316

class classobj_object (object):

    def __repr__ (self):
        """<classobj name at address>"""
        return '<classobj "%s" at 0x%x>' % (
            self.cl_name,
            self.address
            )

class instance_object (object):

    def __repr__ (self):
        """<classname instance [reference count] at address>"""
        return '<%s instance [%d] at 0x%x>' % (
            self.in_class.cl_name.value(),
            self.ob_refcnt,
            self.address
            )

class code_object (object):
    pass

class instancemethod_object (object):
    pass

class function_object (object):

    def __repr__ (self):
        """<function "name" [reference count] at address>"""
        return '<function "%s" [%d] at 0x%x>' % (
            self.func_name.value(),
            get_refcount (self.address),
            self.address,
            )

class traceback_object (object):
    pass

class bool_object (object):

    def __repr__ (self):
        """<bool True|False at address>"""
        if self.address == true_address:
            return '<bool True at 0x%x>' % (self.address)
        elif self.address == false_address:
            return '<bool False at 0x%x>' % (self.address)
        else:
            return '<bool Mystery Value? at 0x%x>' % (self.address)

class classmethod_object:
    pass

class staticmethod_object:
    pass

type_object_table = {
    # associate structures with their types,
    #  unfortunately there's no easy way to automate
    #  this (except for Pyrex types).
    'bool'     : 'PyIntObject',
    'classobj' : 'PyClassObject',
    'code'     : 'PyCodeObject',
    'dict'     : 'PyDictObject',
    'frame'    : 'PyFrameObject',
    'instance' : 'PyInstanceObject',
    'instancemethod' : 'PyMethodObject',
    'int'      : 'PyIntObject',
    'list'     : 'PyListObject',
    'long'     : 'PyLongObject',
    'module'   : 'PyModuleObject',
    'str'      : 'PyStringObject',
    'traceback' : 'PyTracebackObject',
    'tuple'    : 'PyTupleObject',
    'float'    : 'PyFloatObject',
    'function' : 'PyFunctionObject',
    'classmethod' : 'classmethod',
    'staticmethod' : 'staticmethod',
    }

def frob_slots (typo, slots):
    typo.slots = {}
    for name, offset, dtype in slots:
        # a guess, but usually a good one
        is_pointer = (dtype[0] == 'pointer_type')
        typo.slots[name] = is_pointer, offset

def learn_types():
    global type_name_offset
    # hard-code the base object type
    object.slots = slots = {'ob_refcnt': (0, 0), 'ob_type': (1, psize)}
    # bootstrap by learning about type objects
    tt = py_objects['PyTypeObject']
    frob_slots (type_object, tt.slots)
    type_name_offset = type_object.slots['tp_name'][1]
    for addr, name in all_type_objects.iteritems():
        try:
            ob = make_object (addr)
            #print name, ob
        except NotAnObject:
            #print name, addr
            pass
    # fill in slots on known types
    for name, struct in type_object_table.items():
        c = globals()['%s_object' % name]
        s = py_objects[struct]
        frob_slots (c, s.slots)


def format_traceback (tb):
    l = []
    for file, fun, line in tb:
        file = file.split('/')[-1]
        file = file.split('.')[0]
        l.append ('%s:%s:%d' % (file, fun, line))
    return '[' + '|'.join (l) + ']'

def get_traceback (f):
    result = []
    while 1:
        co = f.f_code
        try:
            lineno = real_frame_lineno(f)
        except:
            lineno = -1
        f_back = f.f_back
        result.append ((co.co_filename.value(), co.co_name.value(), lineno))
        if f_back is NULL:
            break
        else:
            f = f_back
    return result

# handy aliases
def MO (address=None):
    if address is None:
        address = _
    return make_object (address)

def MO2 (address=None):
    if address is None:
        address = _
    address = front(address)
    try:
        return make_object (address)
    except:
        try:
            return make_object (address+12)
        except:
            return None

DP = describe_pointer

def real_frame_lineno(frame):
    """Take a frame_object and determine it's "real" current line number.
    """
    code = frame.f_code
    lasti = frame.f_lasti

    lnotab = code.co_lnotab.value()

    size = (len(lnotab) / 2) - 1
    addr = 0

    line = code.co_firstlineno

    i = 0

    while size >= 0:
        addr += ord(lnotab[i])
        i += 1
        if addr > lasti:
            break
        line += ord(lnotab[i])
        i += 1

        size -= 1

    return line

#int
#PyCode_Addr2Line(PyCodeObject *co, int addrq)
#{
#    int size = PyString_Size(co->co_lnotab) / 2;
#    unsigned char *p = (unsigned char*)PyString_AsString(co->co_lnotab);
#    int line = co->co_firstlineno;
#    int addr = 0;
#    while (--size >= 0) {
#        addr += *p++;
#        if (addr > addrq)
#            break;
#        line += *p++;
#    }
#    return line;
#}


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

py_objects = {}

class py_object:

    def __init__ (self, name, dtype, unit):
        self.name = name
        self.nice_name = self._make_nice (name)
        self.dtype = dtype
        self.slots = []
        tag, where, attrs, children = dtype
        for child in children:
            ct, cw, ca, cc = child
            if ct == 'member':
                name = ca['name']
                offset = ca['data_member_location']
                ctype = unit[ca['type']]
                self.slots.append ((name, offset, ctype))
        py_objects[self.name] = self
        #print 'Python Object: %s' % (self.nice_name,)

    def dump (self):
        print '%s' % (self.nice_name,)
        for name, offset, ctype in self.slots:
            print '  %3d : %s (%r)' % (offset, name, ctype)

    def _make_nice (self, name):
        # convert various types of name-mangling
        if name.startswith ('__pyx_obj_'):
            # pyrex object type
            s = name[10:]
            i = 0
            parts = []
            while i < len(s):
                j = i
                while s[j].isdigit():
                    j += 1
                if j > i:
                    n = int (s[i:j])
                    parts.append (s[j:j+n])
                    i = j + n
                    assert (s[i] == '_')
                    i += 1
                else:
                    parts.append (s[i:])
                    break
            return '.'.join (parts)
        else:
            return name

def describe_all_python_objects():
    keys = py_objects.keys()
    keys.sort()
    for key in keys:
        py_objects[key].dump()

all_type_objects = {}

def find_python_objects():
    import parse_dwarf
    for filename, (base, info) in elf_data.iteritems():
        if os.path.split (filename)[-1].startswith ('lib'):
            # files starting with 'libxxx' are
            # unlikely to contain python symbols.
            sys.stderr.write ('skipping %s\n' % (filename,))
            continue
        sys.stderr.write ('dwarfing %s...' % (filename,))
        for unit in parse_dwarf.read (filename, info):
            typo = None
            sys.stderr.write ('.')
            #sys.stderr.write ('scanning %r\n' %  (unit,))
            for child in unit.children:
                tag, where, attrs, children = child
                # how many styles of python object definition?
                if tag == 'typedef' and attrs.has_key('type'):
                    # typedef struct { ... } PyThingObject;
                    # look up structure_type record
                    dtype = unit[attrs['type']]
                    name = attrs['name']
                    if name == 'PyTypeObject':
                        # remember this when we see it
                        typo = where
                elif tag == 'structure_type' and attrs.has_key ('name'):
                    name = attrs['name']
                    if attrs.has_key ('type'):
                        # children defined by reference
                        dtype = unit[attrs['type']]
                    elif children is not None:
                        # children are defined directly
                        dtype = child
                    else:
                        continue
                elif tag == 'variable' and typo and attrs.has_key ('type') and attrs['type'] == typo:
                    # we found a type object
                    if attrs.has_key ('location'):
                        #print 'Type Object: 0x%x %s' % (base + attrs['location'], attrs['name'])
                        all_type_objects[base + attrs['location']] = attrs['name']
                else:
                    continue
                st, sw, sa, sc = dtype
                if sc is not None and len(sc) >= 2:
                    # does it look like a python object?
                    if (sc[0][0] == 'member'
                        and sc[1][0] == 'member'
                        and sc[0][2]['name'] == 'ob_refcnt'
                        and sc[1][2]['name'] == 'ob_type'):
                        py_object (name, dtype, unit)
        sys.stderr.write ('\n')
    print 'found %d python objects' % (len (py_objects),)

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


try:
    import core_utils_local
    # Hack? I think so.
    filename = core_utils_local.__file__
    if filename.endswith('.pyc') or filename.endswith('.pyo'):
        filename = filename[:-1]
    execfile(core_utils_local.__file__[:-1])
    del sys.modules['core_utils_local']
except ImportError:
    pass

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

    type_addr = get_sym ('PyType_Type', address_of=1)
    true_address = get_sym ('_Py_TrueStruct', address_of=1)
    false_address = get_sym ('_Py_ZeroStruct', address_of=1)

    # find all the python-like objects and grok their structures.
    find_python_objects()
    if not py_objects:
        print 'No debugging information in Python binary.  Sorry.'
        sys.exit (-1)

    learn_types()
    #describe_all_python_objects()

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
Welcome to core_utils.

Functions you're most likely to want to use:

    - MO(address): Make an object from an address
    - print_traceback(frame_object): Show a python traceback from a given
      python frame object

See the module docstring (or print __doc__) for detailed usage. Most of the
important functions have docstrings. For example, help(MO).

Once you have an object from MO() help(obj.__repr__) will explain the __repr__
output.
    """

    code.interact(banner=banner, local=locals())
