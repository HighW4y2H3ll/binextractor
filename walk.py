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
    def init(self, binfile, off, size):
        print(binfile)
        print(off)
        print(size)

class LZMA_CB(CALLBACK):
    pass

class SQUASHFS_CB(CALLBACK):
    pass


def dispatch_callback(desc):
    if desc.lower().startswith("lzma compressed data"):
        return LZMA_CB()
    elif desc.lower().startswith("squashfs filesystem"):
        return SQUASHFS_CB()


def extract(binfiles, workdir):
    with binwalk.Modules(*binfiles, signature=True, quiet=True, log=os.path.join(workdir, LOGGING)) as mod:
        executed_mods = mod.execute()
        assert(len(executed_mods) == 1)
        sigmod = executed_mods[0]
        assert(isinstance(sigmod, binwalk.modules.Signature))

        for result in sigmod.results:
            if result.valid:
                cb = dispatch_callback(result.description)
                cb.init(result.file.path, result.offset, result.size)

if __name__ == "__main__":
    extract(sys.argv[1:], ".")
