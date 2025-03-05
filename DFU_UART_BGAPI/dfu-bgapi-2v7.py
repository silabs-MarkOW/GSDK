import sys
import serial

class DFU :
    def __init__(self, uart, baudrate, file) :
        self.sd = serial.Serial(uart, baudrate=baudrate)
        fd = open(file,'rb')
        self.text = fd.read()
        fd.close()
        if len(self.text) & 3 :
            raise RuntimeError('GBL must be 32-bit word length')
        self.state ='start'
    def close(self) :
            self.sd.close()
    def command(self, b) :
        self.sd.write(b)
        resp = self.sd.read(4)
        if resp[1] > 0 :
            resp += self.sd.read(resp[1])
        return resp
    def dfu_reset(self,dfu) :
        return self.command(bytes([0x20,1,0,0,dfu]))
    def flash_set_address(self,address) :
        return self.command(bytes([0x20,4,0,1])+address.to_bytes(4,'little'))
    def flash_upload(self,payload) :
        return self.command(bytes([0x20,1+len(payload),0,2,len(payload)])+payload)
    def flash_upload_finish(self) :
        return self.command(bytes([0x20,0,0,3]))
    def start(self) :
        event = self.dfu_reset(1)
        good = True
        if 0xa0 != event[0] : good = False
        if bytes([0,0]) != event[2:4] : good = False
        if not good :
            raise RuntimeError(event)
        print('Bootloader version: %d.%d.%d'%(event[-1],event[-2],event[-4]|(event[-3]<<8)))
        print('Setting address...',end='')
        resp = self.flash_set_address(0)
        if bytes([0x20,2,0,1,0,0]) != resp :
            raise RuntimeError(resp)
        print('success')
        total = 0
        while len(self.text) > 0 :
            if len(self.text) < 64 :
                chunk = self.text
                self.text = b''
            else :
                chunk = self.text[:64]
                self.text = self.text[64:]
            resp = self.flash_upload(chunk)
            if bytes([0x20,2,0,2,0,0]) != resp :
                raise RuntimeError(resp)
            total += len(chunk)
            print('\rSent %.1f kB'%(total/1024),end='')
        print('\nFinishing upload...',end='')
        resp = self.flash_upload_finish()
        if bytes([0x20,2,0,3,0,0]) != resp :
            raise RuntimeError(resp)
        print('success')
        
dfu = DFU(sys.argv[1],115200,'lemur.gbl')
dfu.start()
dfu.close()
