#!/usr/bin/python3

import sys, os
import importlib

CUR_DIR = os.path.join(os.path.realpath(os.path.dirname(__file__)), 'binwalk/src/binwalk/__init__.py')

#import binwalk
_binwalk_spec = importlib.util.spec_from_file_location('binwalk', CUR_DIR)
binwalk = importlib.util.module_from_spec(_binwalk_spec)
sys.modules[_binwalk_spec.name] = binwalk
_binwalk_spec.loader.exec_module(binwalk)


LOGGING = "log"


import binwalk.core.magic

class CALLBACK(object):
    def __init__(self, binfile):
        self.binfile = binfile
        self.init() # Initialize method from derived class

        self.magic = binwalk.core.magic.Magic(include=['instructions'])
        codesig = os.path.join(os.path.dirname(CUR_DIR), 'magic/binarch')
        self.magic.load(codesig)

    def __del__(self):
        self.cleanup()  # Dtor from derived class

    def __enter__(self):
        pass

    def __exit__(self, typ, val, tb):
        self.cleanup()  # Dtor from derived class

    def update(self, off, size, workdir):
        pass

    def init(self):
        pass

    def cleanup(self):
        pass

    def checkasm(self, code):
        self.magic.reset()
        stat = {
                'mipsel':   0,
                'mips'  :   0,
                'mips16e':  0,
                'mipsel16e':    0,
                'powerpcbe':    0,
                'powerpcle':    0,
                'armeb' :   0,
                'arm'   :   0,
                'ubicom32': 0,
                'avr8'  :   0,
                'avr32' :   0,
                'sparc' :   0,
                'x86'   :   0,
                'coldfire': 0,
                'superh':   0,
                'aarch64':  0,
                }
        for r in self.magic.scan(binwalk.core.compat.bytes2str(code)):
            desc = r.description.lower()
            if desc.startswith("mipsel "):
                stat['mipsel'] += 1
            elif desc.startswith("mips "):
                stat['mips'] += 1
            elif desc.startswith("mips16e "):
                stat['mips16e'] += 1
            elif desc.startswith("mipsel16e "):
                stat['mipsel16e'] += 1
            elif desc.startswith("powerpc big endian"):
                stat['powerpcbe'] += 1
            elif desc.startswith("powerpc little endian"):
                stat['powerpcle'] += 1
            elif desc.startswith("armeb "):
                stat['armeb'] += 1
            elif desc.startswith("arm "):
                stat['arm'] += 1
            elif desc.startswith("ubicom32 "):
                stat['ubicom32'] += 1
            elif desc.startswith("avr8 "):
                stat['avr8'] += 1
            elif desc.startswith("avr32 "):
                stat['avr32'] += 1
            elif desc.startswith("sparc "):
                stat['sparc'] += 1
            elif desc.startswith("intel x86"):
                stat['x86'] += 1
            elif desc.startswith("motorola coldfire"):
                stat['coldfire'] += 1
            elif desc.startswith("superh "):
                stat['superh'] += 1
            elif desc.startswith("aarch64 "):
                stat['aarch64'] += 1

        return max(stat, key=stat.get)


import lzma
class LZMA_CB(CALLBACK):
    def init(self):
        self.index = 0

    def _try_deflate(self, data):
        decomp = lzma.LZMADecompressor()
        unpacked = b""
        stride = 0x10
        for i in range(0, len(data), stride):
            try:
                buf = decomp.decompress(binwalk.core.compat.str2bytes(data[i:i+stride]))
            except IOError as e:
                print("truncated")
                return None, False
            except lzma.LZMAError as e:
                #print(e)
                return unpacked, False
            unpacked += buf
        return unpacked, True

    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        unpacked, valid = self._try_deflate(data)
        if not valid:
            unpacked, valid = self._try_deflate(data[:5]+'\xff'*8+data[5:])

        arch = self.checkasm(unpacked)
        with open(os.path.join(workdir, f"lzma_{self.index}"), 'wb') as fd:
            fd.write(unpacked)

        self.index += 1

class SQUASHFS_CB(CALLBACK):
    pass



class Extractor(object):
    def __init__(self, binfile):
        self.binfiles = [binfile]
        self.lzma_cb = LZMA_CB(binfile)
        self.squashfs_cb = SQUASHFS_CB(binfile)

    def dispatch_callback(self, desc):
        if desc.lower().startswith("lzma compressed data"):
            return self.lzma_cb
        elif desc.lower().startswith("squashfs filesystem"):
            return self.squashfs_cb


    def extract(self, workdir):
        with binwalk.Modules(*self.binfiles, signature=True, quiet=True, log=os.path.join(workdir, LOGGING)) as mod:
            executed_mods = mod.execute()
            assert(len(executed_mods) == 1)
            sigmod = executed_mods[0]
            assert(isinstance(sigmod, binwalk.modules.Signature))

            for result in sigmod.results:
                if result.valid:
                    cb = self.dispatch_callback(result.description)
                    cb.update(result.offset, result.size, workdir)

if __name__ == "__main__":
    for fn in sys.argv[1:]:
        Extractor(fn).extract(".")
