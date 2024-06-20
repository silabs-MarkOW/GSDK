import bincopy
import argparse
import numpy

application_properties_magic = b'\x13\xb7y\xfa\xc9%\xdd\xb7\xad\xf3\xcf\xe0\xf1\xb6\x14\xb8'
bootloader_main_magic = 0x5ECDB007
default_page_size = 2048
default_ram_size = 512 * 1025
bootloader_capabilities = { (1 << 0):"ENFORCE_UPGRADE_SIGNATURE", (1 << 1):"ENFORCE_UPGRADE_ENCRYPTION", (1 << 2):"ENFORCE_SECURE_BOOT", (1 << 4):"BOOTLOADER_UPGRADE", (1 << 5):"GBL", (1 << 6):"GBL_SIGNATURE", (1 << 7):"GBL_ENCRYPTION", (1 << 8):"ENFORCE_CERTIFICATE_SECURE_BOOT", (1 << 9):"ROLLBACK_PROTECTION", (1 << 10):"PERIPHERAL_LIST", (1 << 16):"STORAGE", (1 << 20):"COMMUNICATION" }

class Structure :
    def __init__(self, image, start) :
        self.image = image
        self.start = start
        self.offset = start
    def bytearray(self,length) :
        start = self.offset
        self.offset += length
        stop = self.offset
        ret = image[start:stop]
        return ret
    def uint32(self, length=1) :
        start = self.offset
        stop = start + 4*length
        vector = numpy.frombuffer(self.image[start:start+4*length],numpy.uint32)
        self.offset = stop
        if 1 == length :
            return vector[0]
        return vector

class ApplicationData :
    def __init__(self,version,data) :
        self.types = { 1:'Zigbee', 2:'Thread',4:'Flex',8:'Bluetooth',16:'MCU',32:'Bluetooth app',64:'Bootloader',128:'Zwave' }
        self.type = data.uint32()
        self.version = data.uint32()
        self.capabilities = data.uint32()
        self.productId = data.bytearray(16)
        failure = ''
        if None == self.types.get(self.type) :
            failure += 'Warning: unknown app.type 0x%x\n'%(self.type)
        if len(failure) :
            raise RuntimeError(failure)
            
    def __str__(s) :
        return '{ type:0x%x, version:0x%x, capabilities:0x%x }'%(s.type,s.version,s.capabilities)
    def render(self) :
        ret = self.type.tobytes()
        ret += self.version.tobytes()
        ret += self.capabilities.tobytes()
        return ret

    def show(self) :
        ret = 'Application:\n  Type: %s, Version: 0x%x, Capabilities: 0x%x\n'%(self.types[self.type], self.version, self.capabilities)
        ret += '  productId: %032x\n'%(int.from_bytes(self.productId,'big'))
        return ret
    
class ApplicationProperties :
    def __init__(self, data) :
        self.signatureTypes = { 0:'None', 1:'ECDSA_P256', 2:'CRC32' }
        self.magic = data.bytearray(16)
        self.structVersion = data.uint32()
        if 0x201 == self.structVersion or 0x100 == self.structVersion :
            self.signatureType = data.uint32()
            self.signatureLocation = data.uint32()
            self.app = ApplicationData(self.structVersion,data)
            if None == self.signatureTypes.get(self.signatureType) :
                print('Warning: signatureType: 0x%08x'%(self.signatureType))
        else :
            print('unknown struct version (0x%x)'%(self.structVersion))
            quit()
    def __str__(s) :
        return '{ structVersion:0x%x, signatureType:%d, signatureLocation:0x%x, app:%s }'%(s.structVersion,s.signatureType,s.signatureLocation,s.app.__str__())
    def render(self) :
        ret = self.magic
        ret += self.structVersion.tobytes()
        ret += self.signatureType.tobytes()
        ret += self.signatureLocation.tobytes()
        ret += self.app.render()
        return ret
    def show(self) :
        ret = 'Application Properties\n'
        ret += 'Structure version: %d.%d\n'%(self.structVersion & 0xff, self.structVersion >> 8)
        ret += 'Signature type: %s\n'%(self.signatureTypes.get(self.signatureType))
        ret += 'Signature location: 0x%08x\n'%(self.signatureLocation)
        ret += self.app.show()
        
        return ret

class BootloaderHeader :
    def __init__(self,data) :
        self.magic = data.uint32()
        self.layout = data.uint32()
        self.version = data.uint32()
    def show(self) :
        ret =  '    magic: 0x%08x\n'%(self.magic)
        ret += '    layout: %d\n'%(self.layout)
        ret += '    version: 0x%08x\n'%(self.version)
        return ret
        
class BootloaderTable :
    def __init__(self,data) :
        self.header = BootloaderHeader(data)
        self.size = data.uint32()
        self.startOfAppSpace = data.uint32()
        self.endOfAppSpace = data.uint32()
        self.capabilities = data.uint32()
        self.init = data.uint32()
        self.deinit = data.uint32()
        self.verifyApplication = data.uint32()
        self.initParser = data.uint32()
        self.parseBuffer = data.uint32()
        self.storage = data.uint32()
        if self.header.layout < 2 :
            return
        self.parseImageInfo = data.uint32()
        self.parserContextSize = data.uint32()
        self.remainingApplicationUpgrades = data.uint32()
        self.getPeripheralList = data.uint32()
        self.getUpgradeLocation = data.uint32()
        
    def show(self) :
        ret = 'Bootloader Table:\n'
        ret += '  header:\n' + self.header.show()
        ret += '  size: 0x%x\n'%(self.size)
        ret += '  startOfAppSpace: 0x%x\n'%(self.startOfAppSpace)
        ret += '  endOfAppSpace: 0x%x\n'%(self.endOfAppSpace)
        ret += '  capabilities:\n'
        for i in range(32) :
            if (1 << i) & self.capabilities :
                ret += '    %s\n'%(bootloader_capabilities[1 << i])
        ret += '  init: 0x%x\n'%(self.init)
        ret += '  deinit: 0x%x\n'%(self.deinit)
        ret += '  verifyApplication: 0x%x\n'%(self.verifyApplication)
        ret += '  initParser: 0x%x\n'%(self.initParser)
        ret += '  parseBuffer: 0x%x\n'%(self.parseBuffer)
        ret += '  storage: 0x%x\n'%(self.storage)
        if self.header.layout < 2 :
            return ret
        ret += '  parseImageInfo: 0x%x\n'%(self.parseImageInfo)
        ret += '  parserContextSize: 0x%x\n'%(self.parserContextSize)
        ret += '  remainingApplicationUpgrades: 0x%x\n'%(self.remainingApplicationUpgrades)
        ret += '  getPeripheralList: 0x%x\n'%(self.getPeripheralList)
        ret += '  getUpgradeLocation: 0x%x\n'%(self.getUpgradeLocation)
        return ret

def is_in_range(image, address) :
    if address < image.minimum_address : return False
    if address > image.maximum_address : return False
    return True

def is_application_properties(image,address,debug=False) :
    if not is_in_range(image,address) :
        if debug : print('Reject application properties check on 0x%x out of range'%(address))
        return False
    magic = Structure(image,address).bytearray(16)
    if magic == application_properties_magic :
        if debug : print('Valid application properties magic number at 0x%x'(address))
        return True
    if debug :
        t = int.from_bytes(magic, 'big')
        print('Invalid application properties magic number at 0x%x (%032x)'%(address, t))
    return False
    
# return location of bootloader table
def is_bootloader_table(image, address,debug=False) :
    if not is_in_range(image,address) :
        if debug : print('Reject bootloader table check on 0x%x out of range'%(address))
        return False
    magic = Structure(image,address).uint32()
    if magic == bootloader_main_magic :
        if debug : print('bootloader_main_magic found at 0x%x'%(address))
        return True
    if debug : print('no bootloader_main_magic found at 0x%x (0x%x)'%(address,magic))
    return False

def get_possible_vector_tables(image, page_size=default_page_size, ram_size=default_ram_size, debug=False) :
    start_page = image.minimum_address // page_size
    stop_page =  image.maximum_address // page_size
    if debug : print('testing pages %d to %d'%(start_page, stop_page))
    locations = []
    for page in range(start_page, stop_page) :
        base = page*page_size
        exceptions = Structure(image,base).uint32(16)
        if exceptions[0] < 0x20000000 or exceptions[0] > 0x20000000 + ram_size :
            if debug : print('Reject 0x%x SP=0x%x invalid'%(base,exceptions[0]))
            continue
        for exception in range(1,7) :
            if 0 == (exceptions[1] & 1) : # ISR should be Thumb
                if debug : print('Reject 0x%x exception %d not Thumb'%(base,exception))
                break
            if exceptions[exception] < image.minimum_address :
                if debug : print('Reject 0x%x exception %d too low'%(base,exception))
                break
            if exceptions[exception] > image.maximum_address :
                if debug : print('Reject 0x%x exception %d too high'%(base,exception))
                break
        if debug :
            print('possible vector table at 0x%x, SP=0x%08x, 10:0x%x, 13:0x%x'%(base,exceptions[0],exceptions[10],exceptions[13]))
        locations.append(base)
    return locations

def parse_int(str) :
    suffixes = "kMGT"
    base = 10
    shift = 10 * (1 + suffixes.find(str[-1]))
    if shift :
        str = str[:-1]
    if '0x' == str[:2].lower() :
        str = str[2:]
        base =16
    elif '0' == str[0] :
        str = str[1:]
        base = 8
    return int(str,base) << shift

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='set or show application version number')
    parser.add_argument('-p', '--page-size', help='Flash page size')
    parser.add_argument('-i', '--image', help='Image file', required=True)
    parser.add_argument('-v', '--version', help='Application version to set')
    parser.add_argument('-o', '--output', help='Output image, default is modify image')
    parser.add_argument('-n', '--index', help='index to modify in case of multiple')
    parser.add_argument('-r', '--ram-size', help='RAM size; default %dk'%(default_ram_size>>10))
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug')
    parser.add_argument('-s', '--search', action='store_true', help='Search image for magic')

    args = parser.parse_args()
    if None == args.image :
        parser.print_help()
        quit()
    if args.debug : print(args)

    modify = False
    
    if None == args.ram_size :
        ram_size = default_ram_size
    else :
        ram_size = parse_int(args.ram_size)
    if args.debug : print('ram_size: %d'%(ram_size))
    if None == args.page_size :
        page_size = default_page_size
    else :
        page_size = parse_int(args.page_size)
    if args.debug : print('page_size: %d'%(page_size))
    if None != args.version :
        modify = True
    if None != args.output and not modify :
        print('Warning: --output has no effect if image is not modified')
        
    image = bincopy.BinFile()
    if '.hex' == args.image[-4:] :
        image.add_ihex(open(args.image,'r').read(), 0)
    elif '.s37' == args.image[-4:] :
        image.add_srec(open(args.image,'r').read(), 0)
    else :
        print('Currently only supporting .hex and .s37 images')
        quit()

    page_mask = page_size - 1
    if page_mask & page_size :
        print("page size must be a power of 2")
        quit()
    if image.minimum_address & page_mask :
        print('Warning: starting address 0x%x is not on a page boundary'%(image_minimum_address))

    possible_vector_tables = get_possible_vector_tables(image, page_size=page_size, ram_size=ram_size, debug=args.debug)

    application_properties = []
    bootloader_tables = []
    for base in possible_vector_tables :
        exceptions = Structure(image,base).uint32(16)
        if args.debug : print(exceptions)
        if is_application_properties(image,exceptions[13],debug=args.debug) :
            application_properties.append(exceptions[13])
        if is_bootloader_table(image,exceptions[10],debug=args.debug) :
            bootloader_tables.append(exceptions[10])

    if 0 == len(application_properties) :
        print('No application properties found via exception[13], enabling search')
        args.search = True

    if args.search :
        bytearray = image.as_binary()
        start = 0
        while start < len(bytearray) :
            offset =  bytearray.find(application_properties_magic,start)
            if args.debug : print('offset: 0x%x'%(offset))
            if offset < 0 :
                break
            if args.debug : print('Found application properties magic at offset 0x%x'%(offset))
            ignore = False
            for address in application_properties :
                if address == image.minimum_address + offset :
                    ignore = True
                    break
            if not ignore :
                application_properties.append(image.minimum_address + offset)
            start = offset + len(application_properties_magic)
                
    if not modify :
        for location in application_properties :
            ap = ApplicationProperties(Structure(image,location))
            print('Application Properties found at 0x%x'%(location))
            print(ap.show())
        for location in bootloader_tables :
            print('bootloader table found at 0x%x'%(location))
            bt = BootloaderTable(Structure(image,location))
            print(bt.show())
        quit()
                
    if 1 == len(application_properties) :
        index = 0
    else :
        if None == args.index :
            print('Multiple application properties found, specify index')
            quit()
        else :
            index = int(args.index)

    address = application_properties[index]
    ap = ApplicationProperties(Structure(image,address))

    if None == args.output :
        args.output = args.image

    version = numpy.uint32(args.version)
    ap.app.version = version
    
    sub = ap.render()
    image[address:address+len(sub)] = sub

    if '.hex' == args.output[-4:] :
        open(args.output,'w').write(image.as_ihex())
    elif '.s37' == args.output[-4:] :
        open(args.output,'w').write(image.as_srec())
    else :
        open(args.output,'wb').write(image.as_binary())
