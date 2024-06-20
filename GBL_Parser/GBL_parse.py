import sys
import binascii
'''
    if 0x03A617EB == tag :
        name = 'Header'
        content = 'Data:'
        for i in range(len(data)) :
            content += ' %02x'%(data[i])
    elif 0xF50909F5 == tag :
        name = 'Bootloader'
        crc = binascii.crc32(data[8:],0*0xffffffff)
        content = 'CRC32: %08x / %08x'%(crc,0xffffffff-crc)
        fh = open('dump-bootloader.bin','wb')
        fh.write(data)
        fh.close()
    elif 0xFC0404FC == tag :
        name = 'End'
        content = 'CRC32: %08x'%(getUint32(data))
    else :
        name = 'Illegal/Unknown'
        content = None
'''

def parse_03A617EB(data) :
    version = getUint32(data)
    type = getUint32(data[4:])
    typeDesc = ''
    if 0x100 & type :
        typeDesc = 'signed'
    if 0x1 & type :
        if typeDesc :
            typeDesc += ' and '
        typeDesc += 'encrypted'
    if len(typeDesc) > 0 :
        typeDesc = ' ('+typeDesc+')'
    return ['version: 0x%08x'%(version),
            '   type: 0x%08x%s'%(type,typeDesc)]

def parse_F40A0AF4(data) :
    applicationTypes = ['Zigbee','Thread','Flex','Bluetooth','MCU','Bluetooth App','Bootloader','Z-Wave']
    type = getUint32(data)
    version = getUint32(data[4:])
    capabilities = getUint32(data[8:])
    typeDesc= ''
    for i in range(len(applicationTypes)) :
        if (1 << i) & type :
            if len(typeDesc) > 0 : typeDesc += ' | '
            typeDesc += applicationTypes[i]
    return ['        type: 0x%08x (%s)'%(type,typeDesc),
            '     version: 0x%08x'%(version),
            'capabilities: 0x%08x'%(capabilities)]

def parse_programData(data) :
    startAddress = getUint32(data)
    endAddress = startAddress + len(data) - 5 # last byte written
    return ['Address range: 0x%08x-%08x (%dk-%.1fk)'%(startAddress,endAddress,startAddress>>10,endAddress/1024)]

def parse_end(data) :
    crc32 = getUint32(data)
    return ['CRC32: 0x%08x'%(crc32)]

tags = {
    0x03A617EB: {
        'name': 'GBL Header Tag',
        'desc': 'This must be the first tag in the file. The header tag contains the version number of the GBL file specification, and flags indicating the type of GBL file – whether it is signed or encrypted.',
        'parser': parse_03A617EB
    },
    0xF40A0AF4: {
        'name': 'GBL Application Info Tag',
        'desc': 'This tag contains information about the application update image that is contained in this GBL file',
        'parser': parse_F40A0AF4
    },
    0x5EA617EB: {
        'name': 'GBL SE Upgrade Tag',
        'desc': 'This tag contains a complete encrypted Secure Element update image. Only applicable on Series 2 devices.'
    },
    0xF50909F5: {
        'name': 'GBL Bootloader Tag',
        'desc': 'This tag contains a complete bootloader update image.'
    },
    0xFE0101FE: {
        'name': 'GBL Program Data Tag',
        'desc': 'This tag contains information about what application data to program at a specific address into the main flash memory.',
        'parser': parse_programData
    },
    0xFD0303FD: {
        'name': 'GBL Program Data Tag',
        'desc': 'This tag contains information about what application data to program at a specific address into the main flash memory.',
        'parser': parse_programData
    },
    0xFD0505FD: {
        'name': 'GBL Program LZ4 Compressed Data Tag',
        'desc': 'This tag contains LZ4 compressed information about what application data to program at a specific address into the main flash memory.'
    },
    0xFD0707FD: {
        'name': 'GBL Program LZMA Compressed Data Tag',
        'desc': 'This tag contains LZMA compressed information about what application data to program at a specific address into the main flash memory.'
    },
    0xF60808F6: {
        'name': 'GBL Metadata Tag',
        'desc': 'This tag contains metadata that the bootloader does not parse, but can be returned to the application through a callback.'
    },
    0xF30B0BF3: {
        'name': 'GBL Certificate Tag',
        'desc': 'This tag contains a certificate that will be used to verify the authenticity of the GBL file.'
    },
    0xF70A0AF7: {
        'name': 'GBL Signature Tag',
        'desc': 'This tag contains the ECDSA-P256 signature of all preceding data in the file.'
    },
    0xFC0404FC: {
        'name': 'GBL End Tag',
        'desc': 'This tag indicates the end of the GBL file. It contains a 32-bit CRC for the entire file as an integrity check. The CRC is a noncryptographic check. This must be the last tag.',
        'parser': parse_end
    },
    0xFA0606FA: {
        'name': 'GBL Encryption Init Header',
        'desc': 'This contains information about the image encryption such as the Nonce and the amount of encrypted data.'
    },
    0xF90707F9: {
        'name': 'GBL Encrypted Program Data',
        'desc': 'This contains an encrypted payload containing a plaintext GBL tag, one of Application Info, Bootloader, Metadata or Program Data. The data is encrypted using AES- CTR-128.'
    }
}

argv = sys.argv
argc = len(argv)

if argc < 2 :
    print('Usage: %s <gbl-file>'%(argv[0]))
    quit()

gblFile = argv[1]

def getUint32(b) :
    if len(b) < 4 : raise RuntimeError('bytes to short')
    rc = 0
    for i in range(4) :
        rc <<= 8
        rc += b[3-i]
    return rc

def process(tag,data) :
    tagDesc = tags.get(tag)
    if None == tagDesc :
        name = 'Illegal/Unknown'
        content = None
    else :
        name = tagDesc['name']
        parser = tagDesc.get('parser')
        if None == parser :
            content = None
        else:
            content = parser(data)
        print('Tag: %08x (%s), length: %d'%(tag,name,len(data)))
    if content :
        for line in content :
            print('  %s'%(line))
                       
fh = open(gblFile,'rb')
data = fh.read()
fh.close()

size = len(data)
if size & 3 :
    raise RuntimeError('GBL File size is not a multiple of 4 (%d bytes)'%(size))

offset = 0
while offset < size :
    tag = getUint32(data[offset:])
    offset += 4
    length = getUint32(data[offset:])
    offset += 4
    process(tag,data[offset:offset+length])
    offset += length
crc = binascii.crc32(data[:-4],0*0xffffffff)
print('CRC32: %08x / %08x'%(crc,0xffffffff-crc))
