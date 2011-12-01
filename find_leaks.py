# -*- Mode: Python; tab-width: 4 -*-
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


"""
find_leaks contains some useful utilities for tracking memory.

find_leaks.print_top_n (n)
  Estimate the number of objects of each class throughout
  the system by looking at the reference count of each class object.

find_leaks.process_size ()
  Returns resident and virtual process size in bytes.

find_leaks.object_tracking_mixin
  A mix-in class to keep track of all instances of its subclasses.
"""

import types
import sys
import string
import os
import getrusage
import gc

out = sys.stdout

if hasattr (sys, 'getcounts'):
    # Only activate this if COUNT_ALLOCS is enabled in this python binary.
    # To make a COUNT_ALLOCS binary, follow these steps.
    # Go to the Python source tree.
    # gmake clean
    # gmake count_allocs
    # ./python.count_allocs
    _prev_live = {}
    def live_changes (dont_print=0):
        """live_changes (dont_print=0) -> result
        This function takes a snapshot of objects currently in use.
        Calling it will show you if any new objects were created or
        if the object count for individual object types has changed.

        Typically you call it once, then do something, then call it
        again to see how things have changed in between.

        <dont_print>: If set, the changes are not sent to stdout, but
                      instead or returned as a list of strings.
        """
        global _prev_live
        output = []
        for (name, alloced, freed, max_alloc) in sys.getcounts():
            live = alloced - freed
            if not _prev_live.has_key (name):
                line = "new: %s %d" % (name, live)
            elif _prev_live[name] != live:
                line = "change: %s %d" % (name, live - _prev_live[name])
            else:
                line = None
            if line is not None:
                if dont_print:
                    output.append (line)
                else:
                    print line
            _prev_live[name] = live
        if dont_print:
            return output

def get_refcounts():
    """get_refcounts() -> counts
    Returns the refcount for all Class objects.

    <counts>: Sorted list of (count, class) entries.
              <count> is the reference count.
              <class> is the class object.
    """
    d = {}
    # collect all classes
    for m in sys.modules.values():
        for sym in dir(m):
            o = getattr (m, sym)
            if type(o) is types.ClassType:
                d[o] = sys.getrefcount (o)
    # sort by refcount
    pairs = map (lambda x: (x[1],x[0]), d.items())
    pairs.sort()
    pairs.reverse()
    return pairs

def find_all_types():
    """find_all_types() -> types
    Finds all type objects by scanning all imported modules.

    Note that this will miss any Type objects that are not in the module's
    global namespace.

    <types>: List of type objects.
    """
    d = {}
    # collect all classes
    for m in sys.modules.values():
        for sym in dir(m):
            o = getattr (m, sym)
            ot = type(o)
            if ot is types.TypeType:
                # top-level type object
                d[o] = None
            else:
                d[type(ot)] = None
    all_types = d.keys()
    all_types.sort (lambda a,b: cmp (id(a),id(b)))
    return all_types

def print_type_counts (n=20):
    """print_type_counts (n=20) -> None
    Print a list of the types with the highest refcount.

    <n>: Number of types to display.  Set to 0 to display all of them.
    """
    import mstats
    tl = find_all_types()
    mstats.initialize_type_table (tl)
    cl = mstats.get_type_hist()
    sorted = zip (cl, tl)
    sorted.sort()
    if n:
        sorted = sorted[-n:]
    sorted.reverse()
    for count, type in sorted:
        print '%10d %s' % (count, type)

def print_top_100():
    """print_top_100() -> None
    Alias to print_top_n(100).
    """
    return print_top_n(100)

def print_top_n(num):
    """print_top_n(num) -> None
    Display the classes with the highest refcount.

    <n>: Number of classes to display.
    """
    for n, c in get_refcounts()[:num]:
        print '%10d %s' % (n, c.__name__)


class object_tracking_mixin:

    """object_tracking_mixin

    This is a base class for monitoring the references to instances.

    Inherit this class in your class and call _register_object() in your
    __init__ function.  You now have an _addresses dictionary of all live
    instances.

    <_addresses>: Dictionary with the class object as the key, and a
                  dictionary set of instance addresses.
    """
    _addresses = {}

    def _register_object (self):
        addrs = object_tracking_mixin._addresses.get (self.__class__, {})
        addrs[id(self)] = 1
        object_tracking_mixin._addresses[self.__class__] = addrs

    def __del__ (self):
        del object_tracking_mixin._addresses[self.__class__][id(self)]


_ohw_addresses = {}

class object_hiding_wrapper:

    def __init__ (self, obj):
        self.__dict__['__ido'] = id(obj)
        _ohw_addresses[id(obj)] = obj

    def __getattr__ (self, attr):
        return getattr (_ohw_addresses[self.__dict__['__ido']], attr)

    def __setattr__ (self, attr, value):
        setattr (_ohw_addresses[self.__dict__['__ido']], attr, value)

    def __del__ (self):
        del _ohw_addresses[self.__dict__['__ido']]

def process_size():
    """process_size() -> rsize, vsize
    Returns the resident and virtual size of the process according to the OS.
    """
    # only works on FreeBSD
    if not os.path.exists('/proc/curproc'):
        raise NotImplementedError, "sorry, FreeBSD only right now"
    # read the memory map
    fd = open ('/proc/curproc/map')
    vsize = 0
    # XXX we can probably determine which are resident and use that
    # instead of getrusage, but I don't know how.
    while 1:
        line = fd.readline()
        if not line: break
        [first, second] = line.split ()[:2]
        startaddr = string.atol (first, 16)
        endaddr = string.atol (second, 16)
        vsize += endaddr - startaddr
    fd.close()
    rsize = getrusage.getrusage() [3] * 1024L
    return rsize, vsize

def analyze_strings (cutoff=10, tmpdir='/tmp/'):
    """analyze_strings ([<cutoff>=10], [<tmpdir>='/tmp/']) => None
    dump all strings to a file, then build a histogram of all
    the duplicates with more than <cutoff> identical copies.
    Warning: may use lots of space in <tmpdir>...
    Note: requires /usr/bin/sort.
    """

    def NAME (kind):
        return '%s%s.txt' % (
            os.path.join (tmpdir, 'all_strings'),
            '.' + kind
            )

    import mstats
    print 'dumping... (%s)' % (NAME ('dump'))
    mstats.dump_strings (NAME ('dump'))
    print 'sorting...'
    cmd = 'sort -T %s %s > %s' % (tmpdir, NAME ('dump'), NAME ('sorted'))
    if not os.system (cmd):
        os.unlink (NAME ('dump'))
        print 'building histogram...'
        f = open (NAME ('sorted'), 'rb')
        f2 = open (NAME ('hist'), 'wb')
        last = None
        count = 1
        total = 0
        while 1:
            l = f.readline()
            if not l:
                break
            elif l == last:
                count += 1
            else:
                if count >= cutoff:
                    f2.write ('%10d %r\n' % (count, last))
                    total += 1
                count = 1
                last = l
        if count >= cutoff:
            f2.write ('%10d %r\n' % (count, last))
            total += 1
        f2.close()
        f.close()
        os.unlink (NAME ('sorted'))
        if total:
            cmd = 'sort -T %s -n -k 1,1 %s > %s' % (tmpdir, NAME ('hist'), NAME ('sorted_hist'))
            if not os.system (cmd):
                print 'done.  histogram is in %s' % (NAME ('sorted_hist'),)
            else:
                print 'error sorting histogram'
        else:
            print 'no strings duplicated over %d times' % (cutoff,)
        os.unlink (NAME ('hist'))
    else:
        print 'error sorting string dump'

def why_not_collected(obj, exclude=None):
    """why_not_collected(obj, exclude=None) -> None
    If you call gc.collect(), and then determine that your object is not
    collected as you expect it would (by seeing it in gc.get_objects()),
    use this to figure out why.

    <obj>: The object to investigate.
    <exclude>: Optional list of object to avoid analyzing.
               Typically you would call this with exclude=[dir(), globals()].
    """
    to_visit = [obj]
    visited = set()
    visited.add(id(to_visit))
    visited.add(id(visited))
    if exclude:
        for x in exclude:
            visited.add(id(x))
    while 1:
        try:
            obj = to_visit.pop()
        except IndexError:
            print 'done'
            return
        if id(obj) in visited:
            continue
        if type(obj) == types.FrameType:
            continue
        ref = gc.get_referrers(obj)
        refcount = sys.getrefcount(obj)
        # refcount is +1 because of call to getrefcount() has to INCREF it for
        # the arguments.
        refcount -= 1
        if len(ref) < refcount:
            print 'Leaky object: %r' % obj
            print 'refcount is too high (%i) for number of referrers (%i).' % (refcount, len(ref))
        elif len(ref) > refcount:
            print 'Invalid reference count found for: %r' % obj
            print 'refcount=%i but has too many referrers: %i' % (refcount, len(ref))

        visited.add(id(obj))
        for ref_obj in ref:
            if id(ref_obj) not in visited:
                to_visit.append(obj)


def _main(f):
    global out
    sys.stdout = f
    print_top_n(40)
    rsize, vsize = process_size()
    rsize /= 1024
    vsize /= 1024

    print "Resident size: %dK, Virtual size: %dK" % (rsize, vsize)

from testhelper import dumb_test_maker
unittest_main = dumb_test_maker(_main)

if __name__ == '__main__':
    _main(sys.stdout)
