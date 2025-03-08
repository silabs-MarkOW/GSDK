import bincopy
import sys
import numpy
import argparse

def process(first, last) :
    global page_shift, args
    first_page = first >> page_shift
    last_page = last >> page_shift
    offset = first - (first_page << page_shift)
    last_offset = last - (last_page << page_shift)
    pages = 1 + last_page - first_page 
    print('%d pages: 0x%08x (page %d + %d bytes) to 0x%08x (page %d +  %d bytes)'%(pages, first, first_page, offset, last, last_page, last_offset+1))
    if not args.split :
        return
    filename = 'pages-%03d-to-%03d.hex'%(first_page,last_page)
    fc = bincopy.BinFile(args.image)
    if fc.segments.minimum_address < first :
        fc.segments.remove(fc.segments.minimum_address,first)
    if fc.segments.maximum_address > (last+1) :
        fc.segments.remove(last+1, fc.segments.maximum_address)
    with open(filename,'w') as fd :
        fd.write(fc.as_ihex())
    print('Saved as %s'%(filename))


parser = argparse.ArgumentParser(description='set or show application version number')
parser.add_argument('-p', '--page-size',type=int,default=8192, help='Flash page size (default 8192)')
parser.add_argument('-i', '--image', required=True, help='image to process')
parser.add_argument('-d', '--debug', action='store_true', help='Enable debug')
parser.add_argument('-s', '--split', action='store_true', help='Split image at empty pages')
args = parser.parse_args()
if None == args.image :
    parser.print_help()
    quit()
if args.debug : print(args)
if args.page_size & (args.page_size-1) :
    raise RuntimeError('Page size must be a power of 2')
page_shift = int(numpy.round(numpy.log2(args.page_size)))
f = bincopy.BinFile(args.image)

first =None
last = None
for c in f.segments.chunks() :
    if None == first :
        first = c.address
    if None != last :
        gap = c.address - last
        if 1 != gap :
            process(first,last)
            first = c.address
    last = c.address + len(c.data) - 1

process(first,last)

