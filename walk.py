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



class CALLBACK(object):
    def __init__(self, binfile):
        self.binfile = binfile
        self.init() # Initialize method from derived class

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
