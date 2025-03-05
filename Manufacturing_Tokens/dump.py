import bincopy
import sys

def render_secure_key(data, name) :
    print('#Key extracted from image')
    print('TOKEN_MFG_%s: %032X'%(name, int.from_bytes(data,'big')))

def render_signing_key(data, name) :
    print('#Key extracted from image')
    print('MFG_%s : %064X'%(name, int.from_bytes(data,'big')))
    
class Token :
    def __init__(self, offset, size, name,renderer=None) :
        self.offset = offset
        self.size = size
        self.name = name
        self.renderer = renderer
    def present(self,data) :
        for b in data[self.offset:][:self.size] :
            if 0xff != b : return True
        return False
    def render(self,data) :
        if None == self.renderer : return
        self.renderer(data[self.offset:][:self.size],self.name)

class Tokens :
    def __init__(self,data,start=0x7e000) :
        self.data = data
        self.start = start
        self.list = [
            Token(2,8,'CUSTOM_EUI_64'),
            Token(0x286,16,'SECURE_BOOTLOADER_KEY',render_secure_key),
            Token(0x34c,32,'SIGNED_BOOTLOADER_KEY_X',render_signing_key),
            Token(0x36c,32,'SIGNED_BOOTLOADER_KEY_Y',render_signing_key)]
    def present(self) :
        for token in self.list :
            if token.present(self.data[self.start:]) :
                token.render(self.data[self.start:])
                
tokens = Tokens(bincopy.BinFile(sys.argv[1]))
tokens.present()
