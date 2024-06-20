text = '''
GBL Header Tag 0x03A617EB This must be the first tag in the file. The
header tag contains the version number of
the GBL file specification, and flags indicating the type of GBL file – whether it is signed or encrypted.
GBL Application Info Tag 0xF40A0AF4 This tag contains information about the application update image that is contained in
this GBL file
GBL SE Upgrade Tag 0x5EA617EB This tag contains a complete encrypted Secure Element update image. Only applicable on Series 2 devices.
GBL Bootloader Tag 0xF50909F5 This tag contains a complete bootloader
update image.
GBL Program Data Tag 0xFE0101FE / 0xFD0303FD This tag contains information about what
application data to program at a specific
address into the main flash memory.
GBL Program LZ4 Compressed Data Tag 0xFD0505FD This tag contains LZ4 compressed information about what application data to program
at a specific address into the main flash
memory.
GBL Program LZMA Compressed Data Tag 0xFD0707FD This tag contains LZMA compressed information about what application data to program at a specific address into the main
flash memory.
GBL Metadata Tag 0xF60808F6 This tag contains metadata that the bootloader does not parse, but can be returned
to the application through a callback.
GBL Certificate Tag 0xF30B0BF3 This tag contains a certificate that will be
used to verify the authenticity of the GBL
file.
GBL Signature Tag 0xF70A0AF7 This tag contains the ECDSA-P256 signature of all preceding data in the file.
GBL End Tag 0xFC0404FC This tag indicates the end of the GBL file. It
contains a 32-bit CRC for the entire file as
an integrity check. The CRC is a non-cryptographic check. This must be the last tag.
GBL Header Tag 0x03A617EB The GBL header is the same as for a plaintext GBL file, but the flag indicating that the GBL file is encrypted must be set.
GBL Encryption Init Header Tag 0xFA0606FA This contains information about the image
encryption such as the Nonce and the
amount of encrypted data.
GBL Encrypted Program Data Tag 0xF90707F9 This contains an encrypted payload containing a plaintext GBL tag, one of Application Info, Bootoader, Metadata or Program
Data. The data is encrypted using AESCTR-128.
'''

lines = text.split('\n')
for line in lines :
    #print(line)
    if 'GBL' != line[:3] : continue
    tokens = line.split(' Tag 0x')
    label = tokens[0][4:]
    value = '0x'+tokens[1].split(' ')[0]
    print('  case %s: return "%s";'%(value,label))
