#!/usr/bin/python3

import sys, os
import importlib

CUR_DIR = os.path.abspath(os.path.realpath(os.path.dirname(__file__)))

#import binwalk
BINWALK_DIR = os.path.join(CUR_DIR, 'binwalk/src/binwalk')
_binwalk_init = os.path.join(BINWALK_DIR, "__init__.py")
_binwalk_spec = importlib.util.spec_from_file_location('binwalk', _binwalk_init)
binwalk = importlib.util.module_from_spec(_binwalk_spec)
sys.modules[_binwalk_spec.name] = binwalk
_binwalk_spec.loader.exec_module(binwalk)


LOGGING = "log"


import shutil
def safe_filemove(src, dst):
    while os.path.exists(dst):
        dst += "_"
    shutil.move(src, dst)

def path2name(pstr):
    return pstr.replace('/', '_')


import binwalk.core.magic

class CALLBACK(object):
    def __init__(self, binfile):
        self.binfile = binfile
        self.arch = None
        self.init() # Initialize method from derived class

        self.magic = binwalk.core.magic.Magic(include=['instructions'])
        codesig = os.path.join(BINWALK_DIR, 'magic/binarch')
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

        if max(stat.values()) == 0:
            return None
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
            except EOFError as e:
                return unpacked, True
            unpacked += buf
        return unpacked, True

    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        unpacked, valid = self._try_deflate(data)
        if not valid and len(unpacked) == 0:
            unpacked, valid = self._try_deflate(data[:5]+'\xff'*8+data[5:])

        self.arch = self.checkasm(unpacked)
        with open(os.path.join(workdir, f"lzma_{self.index}"), 'wb') as fd:
            fd.write(unpacked)

        self.index += 1


class SQUASHFS_CB(CALLBACK):
    def init(self):
        self.index = 0

    # TODO: parse squashfs - https://github.com/plougher/squashfs-tools
    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read(size)

        with open(os.path.join(workdir, f"fs_{self.index}.squashfs"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))
        self.index += 1

import io
import zipfile
import tempfile
class ZIP_CB(CALLBACK):
    def init(self):
        self.seen_header = False

    def update(self, off, size, workdir):
        if self.seen_header:
            return
        self.seen_header = True

        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()
        fd.close()

        temp_dir = tempfile.mkdtemp('_tmpx')
        with zipfile.ZipFile(io.BytesIO(binwalk.core.compat.str2bytes(data))) as z:
            for zi in z.infolist():
                if not zi.is_dir():
                    newfn = path2name(zi.filename)
                    with open(os.path.join(temp_dir, newfn), 'wb') as fd:
                        fd.write(z.read(zi))

        for f in os.listdir(temp_dir):
            Extractor(os.path.join(temp_dir, f), toplevel=temp_dir).extract(workdir, extra_file_dir=False)
        d = [sub for sub in os.listdir(workdir) if sub != LOGGING]
        if not d:
            return

        self.arch = max(d, key=d.count)
        for f in os.listdir(os.path.join(workdir, self.arch)):
            safe_filemove(os.path.join(workdir, self.arch, f), os.path.join(workdir, f))
        os.rmdir(os.path.join(workdir, self.arch))

    def reset(self):
        self.seen_header = False

import zlib
import tempfile
class ZLIB_CB(CALLBACK):
    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()
        fd.close()

        unpacked = zlib.decompress(binwalk.core.compat.str2bytes(data))
        temp_dir = tempfile.mkdtemp('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(unpacked)

        Extractor(os.path.join(temp_dir, "tmp"), toplevel=temp_dir).extract(workdir, extra_file_dir=False)
        d = [sub for sub in os.listdir(workdir) if sub != LOGGING]
        if not d:
            return

        self.arch = max(d, key=d.count)
        for f in os.listdir(os.path.join(workdir, self.arch)):
            safe_filemove(os.path.join(workdir, self.arch, f), os.path.join(workdir, f))
        os.rmdir(os.path.join(workdir, self.arch))


class VXWORKS_CB(CALLBACK):
    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        self.arch = self.checkasm(data)

        with open(os.path.join(workdir, "vxworks"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

class HTML_CB(CALLBACK):
    def init(self):
        self.counter = 0

    def update(self, off, size, workdir):
        self.counter += 1


import tempfile
class Extractor(object):
    def __init__(self, binfile, toplevel="/data/firmware/images"):
        self.toplevel = os.path.abspath(os.path.realpath(toplevel))
        self.binfile = os.path.abspath(os.path.realpath(binfile))

        self.lzma_cb = LZMA_CB(self.binfile)
        self.squashfs_cb = SQUASHFS_CB(self.binfile)
        self.zip_cb = ZIP_CB(self.binfile)
        self.zlib_cb = ZLIB_CB(self.binfile)
        self.vxworks_cb = VXWORKS_CB(self.binfile)
        self.html_cb = HTML_CB(self.binfile)

    def dispatch_callback(self, desc):
        if desc.lower().startswith("lzma compressed data"):
            return self.lzma_cb
        elif desc.lower().startswith("squashfs filesystem"):
            return self.squashfs_cb
        elif desc.lower().startswith("zip archive data"):
            return self.zip_cb
        elif desc.lower().startswith("end of zip archive"):
            self.zip_cb.reset()
            # fall through
        elif desc.lower().startswith("zlib compressed data"):
            return self.zlib_cb
        elif desc.lower().startswith("vxworks "):
            return self.vxworks_cb
        elif desc.lower().startswith("html document"):
            return self.html_cb

        # failsafe
        return CALLBACK(self.binfile)


    def extract(self, workdir, extra_file_dir=True):
        temp_dir = tempfile.mkdtemp('_binx')
        with binwalk.Modules(*[self.binfile], signature=True, quiet=True, log=os.path.join(temp_dir, LOGGING)) as mod:
            executed_mods = mod.execute()
            assert(len(executed_mods) == 1)
            sigmod = executed_mods[0]
            assert(isinstance(sigmod, binwalk.modules.Signature))

            assumed_archs = []
            for result in sigmod.results:
                if result.valid:
                    cb = self.dispatch_callback(result.description)
                    cb.update(result.offset, result.size, temp_dir)
                    if cb.arch:
                        assumed_archs.append(cb.arch)

        if not assumed_archs:
            # special case, if we seen a lot html header/footer, that should be the firmware
            if self.html_cb.counter > len(sigmod.results)/2:
                with open(self.binfile, 'rb') as fd:
                    assumed_archs.append(
                            CALLBACK(self.binfile).checkasm(fd.read()))
            if not assumed_archs:
                return False

        arch = max(assumed_archs, key=assumed_archs.count)
        rel_path = os.path.relpath(os.path.dirname(self.binfile), self.toplevel)
        dest_path = os.path.abspath(os.path.join(workdir, arch, rel_path))
        if extra_file_dir:
            dest_path = os.path.join(dest_path, os.path.basename(self.binfile))
        os.makedirs(dest_path, exist_ok=True)
        for fn in os.listdir(temp_dir):
            safe_filemove(os.path.join(temp_dir, fn), os.path.join(dest_path, fn))

        return True

if __name__ == "__main__":
    failed = []
    for fn in sys.argv[1:]:
        try:
            #if not Extractor(fn, os.path.dirname(os.path.abspath(os.path.realpath('.')))).extract("."):
            if not Extractor(fn).extract("."):
                failed.append(fn)
        except:
            failed.append(fn)

    with open("failed", 'a') as fd:
        fd.write('\n'.join(failed))

