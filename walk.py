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

    def update(self, off, size):
        pass

    def init(self):
        pass


class LZMA_CB(CALLBACK):
    def init(self):
        pass

    def update(self, off, size):
        print(self.binfile)
        print(off)
        print(size)
        binwalk.core.common.BlockFile(self.binfile)

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
                    cb.update(result.offset, result.size)

if __name__ == "__main__":
    for fn in sys.argv[1:]:
        Extractor(fn).extract(".")
