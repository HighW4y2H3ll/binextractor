#!/usr/bin/python3

import sys, os
import importlib

CUR_DIR = os.path.abspath(os.path.realpath(os.path.dirname(__file__)))
WORKSPACE = os.path.join(CUR_DIR, "workspace")
FAIL_LOG = os.path.join(WORKSPACE, f"failed-{os.getpid()}")

DEBUG = False

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
    if pstr[0] == '.':
        pstr = pstr[1:]
    return pstr.replace('/', '_')

file_blacklist = [
        'makefile', 'copying', 'install-sh', 'configure',
        'configure.in', 'makefile.in', 'readme', 'changelog',
        'install', 'todo', 'aclocal.m4', 'authors', 'faq', 'howto',
        'thanks', 'license', 'kconfig', 'kbuild',
        ]
dir_blacklist = ['toolchain', 'tools']
extension_blacklist = [
        '.sh', '.bat', '.c', '.h', '.cpp', '.hpp', '.mak',
        '.make', '.js', '.xml', '.html', '.htm', '.css', '.svn-base',
        '.s', '.txt', '.in', '.asm', '.am', '.log', '.pl', '.png', '.jpg',
        '.gif', '.bmp', '.conf', '.texi', '.plo', '.tex', '.man', '.8',
        '.sgml', '.diff', '.patch', '.txt', '.pdf',
        ]

def interesting_path(pstr):
    flag = False
    for f in file_blacklist:
        flag |= (pstr.lower() == f)
        flag |= pstr.lower().endswith('/'+f)
    for d in dir_blacklist:
        flag |= pstr.lower().startswith(d)
        flag |= ((d+'/') in pstr.lower())
        flag |= (('/'+d) in pstr.lower())
    for ext in extension_blacklist:
        flag |= pstr.lower().endswith(ext)
    return not flag

def path_flatten(pstr, toplevel=None):
    if os.path.isfile(pstr):
        if not interesting_path(pstr):
            return
        if toplevel:
            relp = os.path.relpath(pstr, toplevel)
            newfn = path2name(relp)
            if newfn != pstr:
                shutil.move(pstr, os.path.join(toplevel, newfn))
        return
    if not toplevel:    toplevel = pstr
    subs = os.listdir(pstr)
    for d in subs:
        path_flatten(os.path.join(pstr, d), toplevel)
    # remove all sub directories
    subs = os.listdir(pstr)
    for d in subs:
        if os.path.isdir(d):
            shutil.rmtree(d)

def list_files(pstr):
    res = []
    for (root, dirs, files) in os.walk(pstr):
        for f in files:
            p = os.path.join(root, f)
            if interesting_path(p):
                res.append(p)
    return res

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

    def workspace_cleanup(self, workdir):
        archs = [sub for sub in os.listdir(workdir) if not sub.startswith(LOGGING)]
        if not archs:
            return

        self.arch = max(archs, key=lambda x:len(os.listdir(os.path.join(workdir, x))))

        # clean up wrong arch/subdir
        for d in os.listdir(workdir):
            if os.path.isdir(os.path.join(workdir, d)) and d != self.arch:
                shutil.rmtree(os.path.join(workdir, d))

        # flatten dir
        for f in os.listdir(os.path.join(workdir, self.arch)):
            safe_filemove(os.path.join(workdir, self.arch, f), os.path.join(workdir, f))
        shutil.rmtree(os.path.join(workdir, self.arch))

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
                if not zi.is_dir() and interesting_path(zi.filename):
                    newfn = path2name(zi.filename)
                    with open(os.path.join(temp_dir, newfn), 'wb') as fd:
                        fd.write(z.read(zi))

        for f in list_files(temp_dir):
            Extractor(f, toplevel=temp_dir).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

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

        try:
            unpacked = zlib.decompress(binwalk.core.compat.str2bytes(data))
        except zlib.error as e:
            #print("invalid zlib")
            return

        temp_dir = tempfile.mkdtemp('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(unpacked)

        Extractor(os.path.join(temp_dir, "tmp"), toplevel=temp_dir).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import tempfile
import subprocess
class RAR_CB(CALLBACK):
    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = tempfile.mkdtemp('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        # unrar : https://www.rarlab.com/rar_add.htm
        temp_workdir = tempfile.mkdtemp('_tmpx')
        subprocess.check_call(
                ["./unrar/unrar", "x", "-y", "-p-", os.path.join(temp_dir, "tmp"), temp_workdir],
                stdout=subprocess.DEVNULL)

        path_flatten(temp_workdir)

        for f in list_files(temp_workdir):
            Extractor(f, toplevel=temp_workdir).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)
            shutil.rmtree(temp_workdir)

import io
import gzip
class GZIP_CB(CALLBACK):
    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        unpacked = b""
        stride = 0x10
        gz = gzip.GzipFile(fileobj=io.BytesIO(binwalk.core.compat.str2bytes(data)))
        for i in range(0, len(data), stride):
            try:
                buf = gz.read(stride)
            except zlib.error as e:
                #print("invalid gzip")
                return
            except OSError as e:
                #print("invalid gzip")
                break
            unpacked += buf

        temp_dir = tempfile.mkdtemp('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(unpacked)

        Extractor(os.path.join(temp_dir, "tmp"), toplevel=temp_dir).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import bz2
class BZIP2_CB(CALLBACK):
    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        unpacked = bz2.decompress(binwalk.core.compat.str2bytes(data))

        temp_dir = tempfile.mkdtemp('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(unpacked)

        Extractor(os.path.join(temp_dir, "tmp"), toplevel=temp_dir).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        # shutil.rmtree(temp_dir)

import io
import tarfile
import tempfile
class TAR_CB(CALLBACK):
    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        try:
            tar = tarfile.TarFile(fileobj=io.BytesIO(binwalk.core.compat.str2bytes(data)))
        except tarfile.InvalidHeaderError as e:
            return

        temp_dir = tempfile.mkdtemp('_tmpx')
        for m in tar.getmembers():
            if m.isfile() and interesting_path(m.name):
                buf = tar.extractfile(m)
                with open(os.path.join(temp_dir, path2name(m.name)), 'wb') as fd:
                    fd.write(buf.read())

        for f in list_files(temp_dir):
            Extractor(f, toplevel=temp_dir).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)


class VXWORKS_CB(CALLBACK):
    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        self.arch = self.checkasm(data)

        #with open(os.path.join(workdir, "vxworks"), 'wb') as fd:
        #    fd.write(binwalk.core.compat.str2bytes(data))

class HTML_CB(CALLBACK):
    def init(self):
        self.counter = 0

    def update(self, off, size, workdir):
        self.counter += 1

class ELF_CB(CALLBACK):
    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read(0x1000)  # read first page

        self.arch = self.checkasm(data)

class LINUXKERN_CB(CALLBACK):
    def update(self, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(0)
        data = fd.read()

        self.arch = self.checkasm(data)


import re
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
        self.rar_cb = RAR_CB(self.binfile)
        self.gzip_cb = GZIP_CB(self.binfile)
        self.elf_cb = ELF_CB(self.binfile)
        self.bzip2_cb = BZIP2_CB(self.binfile)
        self.tar_cb = TAR_CB(self.binfile)
        self.linuxkern_cb = LINUXKERN_CB(self.binfile)

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
        elif desc.lower().startswith("rar archive"):
            return self.rar_cb
        elif desc.lower().startswith("gzip compressed data"):
            # Trim out uninterested file extensions - Wind River System
            match = re.search("has original file name: \"(.+?)\",",desc.lower())
            if not match or interesting_path(match.group(1)):
                return self.gzip_cb
            else:
                return self.html_cb # re-use html indicator
        elif desc.lower().startswith("elf, "):
            return self.elf_cb
        elif desc.lower().startswith("bzip2 compressed data"):
            return self.bzip2_cb
        elif desc.lower().startswith("posix tar archive"):
            return self.tar_cb
        elif desc.lower().startswith("linux kernel version"):
            return self.linuxkern_cb

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

        # special case, if we seen a lot html header/footer, that should be the firmware
        if self.html_cb.counter >= len(sigmod.results)/2:
            with open(self.binfile, 'rb') as fd:
                check_arch = CALLBACK(self.binfile).checkasm(fd.read())
            if check_arch:
                for i in range(self.html_cb.counter):
                    assumed_archs.append(check_arch)
                shutil.copy(self.binfile, temp_dir)
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

import traceback
if __name__ == "__main__":
    failed = []
    for fn in sys.argv[1:]:
        print(fn)
        try:
            #if not Extractor(fn, os.path.dirname(os.path.abspath(os.path.realpath('.')))).extract("."):
            if not Extractor(fn).extract(WORKSPACE):
                failed.append(fn)
        except:
            traceback.print_exception(*sys.exc_info())
            print(f"Unpack Failed: {fn}")
            failed.append(fn)

    with open(FAIL_LOG, 'a') as fd:
        fd.write('\n'.join(failed) + '\n')

