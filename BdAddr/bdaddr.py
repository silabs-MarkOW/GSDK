#! /bin/env python3

import sys
if len(sys.argv) != 2 :
    raise RuntimeError('Usage: bdaddr <address>')

def get_address(s) :
    octets = s.split(':')
    if len(octets) != 6 :
        raise RuntimeError('currently only support xx:xx:xx:xx:xx:xx style')
    acc = 0
    for octet in octets :
        acc <<= 8
        acc |= int(octet, 16)
    return acc

addr = int.to_bytes(get_address(sys.argv[1]),6,'little')
print("{ .addr = { %s } }"%(', '.join(['0x%02x'%(x) for x in addr])))

                
