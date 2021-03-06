#!/usr/bin/python3

import sys, os
import importlib

CUR_DIR = os.path.abspath(os.path.realpath(os.path.dirname(__file__)))
WORKSPACE = os.path.join(CUR_DIR, "workspace")
TEMP = os.path.join(CUR_DIR, "temp")
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


import stat
import shutil
def safe_filemove(src, dst):
    counter = 0
    orig = dst.split('.')[0]
    while os.path.exists(dst):
        dst = f"{orig}.{str(counter)}"
        counter += 1
    shutil.move(src, dst)

def safe_filecopy(src, dst):
    counter = 0
    orig = dst.split('.')[0]
    while os.path.exists(dst):
        dst = f"{orig}.{str(counter)}"
        counter += 1
    shutil.copy(src, dst)

def safe_mkdir(parent, ndir):
    counter = 0
    orig = ndir.split('.')[0]
    np = os.path.join(parent, ndir)
    while os.path.exists(np):
        np = os.path.join(parent, f"{orig}.{str(counter)}")
        counter += 1
    os.mkdir(np)
    return np

import tempfile
def make_tempdir(suffix):
    return tempfile.mkdtemp(suffix, dir=TEMP)

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
        '.bat', '.c', '.h', '.cpp', '.hpp', '.mak',
        '.make', '.js', '.xml', '.html', '.htm', '.css', '.svn-base',
        '.s', '.txt', '.in', '.asm', '.am', '.log', '.png', '.jpg',
        '.gif', '.bmp', '.conf', '.texi', '.plo', '.tex', '.man', '.8',
        '.sgml', '.diff', '.patch', '.txt', '.pdf', '.class', '.jar',
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
        if os.path.isdir(os.path.join(pstr, d)):
            shutil.rmtree(os.path.join(pstr, d))

def list_files(pstr):
    res = []
    for (root, dirs, files) in os.walk(pstr):
        for f in files:
            p = os.path.join(root, f)
            if interesting_path(p):
                res.append(p)
    return res

rootfs_toplevel = [
        'usr', 'etc', 'opt', 'var',
        'bin', 'sbin',
        ]
def check_rootfsdir(pstr):
    return os.path.basename(os.path.abspath(pstr)) in rootfs_toplevel

def special_dev(path):
    try:
        mode = os.stat(path).st_mode
    except:
        return True
    return stat.S_ISBLK(mode) or stat.S_ISCHR(mode)

def ignore_cb(path, names):
    return set(name for name in names if special_dev(os.path.join(path, name)) or name=='lost+found')

import subprocess
def treecopy(src, dst):
    if os.path.exists(dst):
        os.rmdir(dst)
    result = subprocess.call(
            ["sudo", "chmod", "-R", "+r", src],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL)
    try:
        shutil.copytree(src, dst, symlinks=True, ignore=ignore_cb)
    except shutil.Error as e:
        errors = [err for err in e.args[0] if err[2]!='[Errno 5] Input/output error']
        if errors:
            raise shutil.Error(errors)


import binwalk.core.magic

import gzip
class CALLBACK(object):
    def __init__(self, binfile, recursion_level):
        self.binfile = binfile
        self.level = recursion_level
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

    def update(self, desc, off, size, workdir):
        pass

    def init(self):
        pass

    def cleanup(self):
        pass

    def save(self, dest, data):
        destdir = os.path.dirname(dest)
        if not os.path.exists(destdir):
            os.makedirs(destdir, exist_ok=True)
        counter = 0
        orig = os.path.basename(dest).split('.')[0]
        while os.path.exists(dest):
            dest = os.path.join(destdir, f"{orig}.{str(counter)}")
            counter += 1
        with open(dest, 'wb') as fd:
            fd.write(data)

    def _checkbFLT(self, results):
        for r in results:
            if r.description.lower().startswith("bflt executable") \
                    and "gzip" in r.description.lower():
                return True
        return False

    def rootfs_handler(self, workdir, destdir, unpack_cb):
        # cleanup workdir
        #for sub in os.listdir(workdir):
        #    shutil.rmtree(os.path.join(workdir, sub))

        unpacked_dir = safe_mkdir(workdir, "unpacked")
        unpack_cb(unpacked_dir)

        # infer arch
        assumed_archs = []
        magic = binwalk.core.magic.Magic(include=['.*'])
        exesig = os.path.join(BINWALK_DIR, 'magic/executables')
        magic.load(exesig)
        for root, _, files in os.walk(unpacked_dir):
            for f in files:
                if os.path.islink(os.path.join(root, f)):
                    continue
                if special_dev(os.path.join(root, f)):
                    continue
                if not interesting_path(f):
                    continue
                with open(os.path.join(root, f), 'rb') as fd:
                    code = fd.read()
                results = magic.scan(binwalk.core.compat.bytes2str(code))
                if results:
                    if self._checkbFLT(results):
                        try:
                            gz = gzip.GzipFile(fileobj=io.BytesIO(code[0x40:]))
                            unpacked = b""
                            for i in range(0, len(code[0x40:]), 1024):
                                unpacked += gz.read(1024)
                        except EOFError as e:
                            pass
                        code = unpacked
                    arch = self.checkasm(code)
                    if arch:
                        assumed_archs.append(arch)

        if not assumed_archs:
            return
        arch = max(assumed_archs, key=assumed_archs.count)

        # copy results
        if arch:
            dest = os.path.join(destdir, arch)
            os.makedirs(dest, exist_ok=True)
            safe_filemove(unpacked_dir, os.path.join(dest, os.path.basename(unpacked_dir)))
            safe_filecopy(self.binfile, os.path.join(dest, os.path.basename(self.binfile)))

    def workspace_cleanup(self, workdir, flatten_dir=False):
        archs = [sub for sub in os.listdir(workdir) if os.path.isdir(os.path.join(workdir, sub))]
        if not archs:
            return

        self.arch = max(archs, key=lambda x:len(os.listdir(os.path.join(workdir, x))))

        # clean up wrong arch/subdir
        for d in os.listdir(workdir):
            if os.path.isdir(os.path.join(workdir, d)) and d != self.arch:
                shutil.rmtree(os.path.join(workdir, d))

        # flatten dir
        if flatten_dir:
            for f in os.listdir(os.path.join(workdir, self.arch)):
                safe_filemove(os.path.join(workdir, self.arch, f), os.path.join(workdir, f))
            shutil.rmtree(os.path.join(workdir, self.arch))

    def checkasm(self, code):
        self.magic.reset()
        stat = {
                'mips64':   0,
                'mips64el': 0,
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
            if desc.startswith("mips 64 "):
                stat['mips64'] += 1
            elif desc.startswith("mipsel 64 "):
                stat['mips64el'] += 1
            elif desc.startswith("mipsel "):
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

    def _try_deflate(self, data, fout):
        ldat = 0
        decomp = lzma.LZMADecompressor()
        stride = 0x10
        for i in range(0, len(data), stride):
            try:
                unpacked = decomp.decompress(binwalk.core.compat.str2bytes(data[i:i+stride]))
            except IOError as e:
                print("truncated")
                return None, False
            except lzma.LZMAError as e:
                #print(e)
                return ldat, False
            except EOFError as e:
                return ldat, True
            fout.write(unpacked)
            ldat += len(unpacked)
        return ldat, True

    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir("_tmpx")
        with open(os.path.join(temp_dir, "tmp"), 'wb') as tmpfd:
            ldat, valid = self._try_deflate(data, tmpfd)
            if not valid and ldat == 0:
                tmpfd.seek(0)
                tmpfd.truncate(0)
                ldat, valid = self._try_deflate(data[:5]+'\xff'*8+data[5:], tmpfd)

        Extractor(os.path.join(temp_dir, "tmp"), toplevel=temp_dir, recursion_level=self.level+1).extract(workdir, extra_file_dir=False)
        self.workspace_cleanup(workdir)

        if not self.arch:
            with open(os.path.join(temp_dir, "tmp"), 'rb') as fd:
                unpacked = fd.read()
                self.arch = self.checkasm(unpacked)
                if self.arch:
                    self.save(os.path.join(workdir, self.arch, f"lzma_{self.index}"), unpacked)

        if self.arch:
            self.index += 1
        if not DEBUG:
            shutil.rmtree(temp_dir)

import shutil
class XZ_CB(CALLBACK):
    def init(self):
        self.index = 0

    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir("_tmpx")
        decomp = lzma.LZMADecompressor()
        stride = 0x10
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            for i in range(0, len(data), stride):
                try:
                    unpacked = decomp.decompress(binwalk.core.compat.str2bytes(data[i:i+stride]))

                    fd.write(unpacked)
                except lzma.LZMAError as e:
                    break
                except EOFError as e:
                    break

        self.index += 1

        Extractor(os.path.join(temp_dir, "tmp"), toplevel=temp_dir, recursion_level=self.level+1).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)


class SQUASHFS_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        def unpack_cb(unpackdir):
            os.rmdir(unpackdir)
            result = subprocess.call(
                    ["sasquatch", "-d", unpackdir, os.path.join(temp_dir, "tmp")],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
        self.rootfs_handler(temp_dir, workdir, unpack_cb)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import shutil
class CRAMFS_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        def unpack_cb(unpackdir):
            os.rmdir(unpackdir)
            result = subprocess.call(
                    ["./util-linux/fsck.cramfs", "-x", unpackdir, os.path.join(temp_dir, "tmp")],
                    stdout=subprocess.DEVNULL)
        self.rootfs_handler(temp_dir, workdir, unpack_cb)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import shutil
class EXTFS_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        def unpack_cb(unpackdir):
            tempd = make_tempdir('_tmpx')
            result = subprocess.call(
                    ["sudo", "mount", os.path.join(temp_dir, "tmp"), tempd],
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL)
            if os.listdir(tempd):
                treecopy(tempd, unpackdir)
                result = subprocess.call(
                        ["sudo", "umount", tempd],
                        stderr=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL)
                shutil.rmtree(tempd)
            else:
                os.rmdir(tempd)
                os.rmdir(unpackdir)
                result = subprocess.call(
                        ["tsk_recover", "-i", "raw", "-f", "ext", "-a", os.path.join(temp_dir, "tmp"), unpackdir],
                        stderr=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL)
        self.rootfs_handler(temp_dir, workdir, unpack_cb)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import shutil
class ROMFS_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        def unpack_cb(unpackdir):
            tempd = make_tempdir('_tmpx')
            result = subprocess.call(
                    ["sudo", "mount", "-t", "romfs", os.path.join(temp_dir, "tmp"), tempd],
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL)
            treecopy(tempd, unpackdir)
            result = subprocess.call(
                    ["sudo", "umount", tempd],
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL)
            shutil.rmtree(tempd)
        self.rootfs_handler(temp_dir, workdir, unpack_cb)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import shutil
class JFFS2FS_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        def unpack_cb(unpackdir):
            tempd = make_tempdir('_tmpx')
            result = subprocess.call(
                    ["sudo", "mount", "-t", "jffs2", os.path.join(temp_dir, "tmp"), tempd],
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL)
            treecopy(tempd, unpackdir)
            result = subprocess.call(
                    ["sudo", "umount", tempd],
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL)
            shutil.rmtree(tempd)
        self.rootfs_handler(temp_dir, workdir, unpack_cb)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import shutil
class UBIFS_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        def unpack_cb(unpackdir):
            tempd = make_tempdir('_tmpx')
            result = subprocess.call(
                    ["sudo", "mount", "-t", "ubifs", os.path.join(temp_dir, "tmp"), tempd],
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL)
            treecopy(tempd, unpackdir)
            result = subprocess.call(
                    ["sudo", "umount", tempd],
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL)
            shutil.rmtree(tempd)
        self.rootfs_handler(temp_dir, workdir, unpack_cb)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import shutil
class YAFFS_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        def unpack_cb(unpackdir):
            os.rmdir(unpackdir)
            result = subprocess.call(
                    ["./yaffshiv/src/yaffshiv", "--auto", "--brute-force","-d", unpackdir, "-f", os.path.join(temp_dir, "tmp")],
                    stdout=subprocess.DEVNULL)
        self.rootfs_handler(temp_dir, workdir, unpack_cb)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

from dlromfs import RomFS
class DLROMFS_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        def unpack_cb(unpackdir):
            fs = RomFS(os.path.join(temp_dir, "tmp"))
            for (uid, info) in fs.entries.items():
                if hasattr(info, 'name') and hasattr(info, 'parent'):
                    path = fs.build_path(uid).strip(os.path.sep)
                    fname = os.path.join(unpackdir, path)

                    if info.type == "directory" and not os.path.exists(fname):
                        os.makedirs(fname)
                    else:
                        fdata = fs.get_data(uid)
                        with open(fname, 'wb') as fp:
                            fp.write(fdata)
        self.rootfs_handler(temp_dir, workdir, unpack_cb)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

from pfs import PFS
class PFS_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        def unpack_cb(unpackdir):
            with PFS(os.path.join(temp_dir, "tmp")) as fs:
                data = binwalk.core.common.BlockFile(os.path.join(temp_dir, "tmp"), 'rb')
                data.seek(fs.get_end_of_meta_data())
                for entry in fs.entries():
                    outfile_path = os.path.abspath(os.path.join(unpackdir, entry.fname))
                    if not os.path.exists(os.path.dirname(outfile_path)):
                        os.makedirs(os.path.dirname(outfile_path), exist_ok=True)
                    outfile = binwalk.core.common.BlockFile(outfile_path, 'wb')
                    outfile.write(data.read(entry.fsize))
                    outfile.close()
                data.close()
        self.rootfs_handler(temp_dir, workdir, unpack_cb)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import io
import struct
import zipfile
class ZIP_CB(CALLBACK):
    def init(self):
        self.head_off = -1
        self.total = 0
        self.interesting = 0
        self.seen_zip = False

    def update(self, desc, off, size, workdir):
        self.seen_zip = True
        match = re.search(", name: (.+?)$",desc.lower())
        if not match or interesting_path(match.group(1)):
            self.interesting += 1
        self.total += 1

        if self.head_off == -1 or off < self.head_off:
            self.head_off = off

        return self._handle_central_dir

    def _handle_central_dir(self, result, caller, workdir):
        if not result.description.lower().startswith("end of zip archive"):
            return
        if self.interesting == 0:
            return
        if not self.seen_zip:
            return
        self.seen_zip = False

        cur_offset = result.offset + 20
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(cur_offset)
        comment_size = struct.unpack('<H', binwalk.core.compat.str2bytes(fd.read(2)))[0]
        cur_offset += 2 + comment_size
        fd.seek(self.head_off)
        data = fd.read(cur_offset - self.head_off)
        fd.close()

        found_fs = False
        temp_dir = make_tempdir('_tmpx')
        try:
            with zipfile.ZipFile(io.BytesIO(binwalk.core.compat.str2bytes(data))) as z:
                for zi in z.infolist():
                    if zi.is_dir() and check_rootfsdir(zi.filename):
                        found_fs = True
                        break
                    if not zi.is_dir() and interesting_path(zi.filename):
                        newfn = path2name(zi.filename)
                        with open(os.path.join(temp_dir, newfn), 'wb') as fd:
                            fd.write(z.read(zi))
        except zipfile.BadZipFile as e:
            #print("Bad Zip File")
            pass
        except ValueError as e:
            pass

        if found_fs:
            def unpack_cb(unpackdir):
                try:
                    with zipfile.ZipFile(io.BytesIO(binwalk.core.compat.str2bytes(data))) as z:
                        z.extractall(unpackdir)
                except zipfile.BadZipFile as e:
                    pass
            self.rootfs_handler(temp_dir, workdir, unpack_cb)
        else:
            for f in list_files(temp_dir):
                Extractor(f, toplevel=temp_dir, recursion_level=self.level+1).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

        caller.callnext = None
        if self.arch:
            caller.assumed_archs.append(self.arch)

import zlib
class ZLIB_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()
        fd.close()

        try:
            unpacked = zlib.decompress(binwalk.core.compat.str2bytes(data))
        except zlib.error as e:
            #print("invalid zlib")
            return

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(unpacked)

        Extractor(os.path.join(temp_dir, "tmp"), toplevel=temp_dir, recursion_level=self.level+1).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import subprocess
class RAR_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        # unrar : https://www.rarlab.com/rar_add.htm
        temp_workdir = make_tempdir('_tmpx')
        result = subprocess.call(
                ["./unrar/unrar", "x", "-y", "-p-", os.path.join(temp_dir, "tmp"), temp_workdir],
                stdout=subprocess.DEVNULL)

        # NOTE: didn't see rar packed rootfs yet
        path_flatten(temp_workdir)

        for f in list_files(temp_workdir):
            Extractor(f, toplevel=temp_workdir, recursion_level=self.level+1).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)
            shutil.rmtree(temp_workdir)

import io
import gzip
class GZIP_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        stride = 10 * 1024  # let's trust binwalk plugin for the block size for now
        gz = gzip.GzipFile(fileobj=io.BytesIO(binwalk.core.compat.str2bytes(data)))

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            for i in range(0, len(data), stride):
                try:
                    unpacked = gz.read(stride)
                except zlib.error as e:
                    #print("invalid gzip")
                    break
                except OSError as e:
                    #print("invalid gzip")
                    break
                except EOFError as e:
                    break
                fd.write(unpacked)

        Extractor(os.path.join(temp_dir, "tmp"), toplevel=temp_dir, recursion_level=self.level+1).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import bz2
class BZIP2_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        try:
            unpacked = bz2.decompress(binwalk.core.compat.str2bytes(data))
        except OSError as e:
            return

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(unpacked)

        Extractor(os.path.join(temp_dir, "tmp"), toplevel=temp_dir, recursion_level=self.level+1).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import io
import tarfile
class TAR_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        try:
            tar = tarfile.TarFile(fileobj=io.BytesIO(binwalk.core.compat.str2bytes(data)))
        except tarfile.InvalidHeaderError as e:
            #print("Tar Error: invalid Headder")
            return
        except tarfile.ReadError as e:
            return

        found_fs = False
        temp_dir = make_tempdir('_tmpx')
        try:
            for m in tar:
                if m.isdir() and check_rootfsdir(m.name):
                    found_fs = True
                    break
                if m.isfile() and interesting_path(m.name):
                    buf = tar.extractfile(m)
                    with open(os.path.join(temp_dir, path2name(m.name)), 'wb') as fd:
                        fd.write(buf.read())
        except tarfile.ReadError as e:
            #print("corrupted tar file")
            pass

        if found_fs:
            def unpack_cb(unpackdir):
                try:
                    for ti in tar:
                        if ti.ischr() or ti.isblk():
                            continue
                        tar.extract(ti, unpackdir, set_attrs=not ti.isdir())
                except tarfile.ReadError as e:
                    pass
            self.rootfs_handler(temp_dir, workdir, unpack_cb)
        else:
            for f in list_files(temp_dir):
                Extractor(f, toplevel=temp_dir, recursion_level=self.level+1).extract(workdir, extra_file_dir=False)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)

import io
import subprocess
class CPIO_CB(CALLBACK):
    def cpio_end(self, result, caller, workdir):
        caller.skip = True
        if not result.description.lower().startswith("ascii cpio archive"):
            caller.skip = False
            caller.callnext = None

    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        temp_dir = make_tempdir('_tmpx')
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        # possible filesystem, try unpack
        def unpack_cb(unpackdir):
            with open(os.path.join(temp_dir, "tmp"), 'rb') as fdin:
                result = subprocess.call(
                        ["cpio", "-d", "-i", "--no-absolute-filenames"],
                        cwd=unpackdir,
                        stdin=fdin,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
        self.rootfs_handler(temp_dir, workdir, unpack_cb)

        self.workspace_cleanup(workdir)
        if not DEBUG:
            shutil.rmtree(temp_dir)
        return self.cpio_end


class VXWORKS_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read()

        self.arch = self.checkasm(data)

        if self.arch:
            self.save(os.path.join(workdir, self.arch, "vxworks"), binwalk.core.compat.str2bytes(data))

class XEROXDLM_CB(CALLBACK):
    def _unpack_data(self, result, caller, workdir):
        caller.callnext = None

        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(result.offset)
        data = fd.read()

        temp_dir = make_tempdir("_tmpx")
        with open(os.path.join(temp_dir, "tmp"), 'wb') as fd:
            fd.write(binwalk.core.compat.str2bytes(data))

        extractor = Extractor(os.path.join(temp_dir, "tmp"), toplevel=temp_dir, recursion_level=self.level+1)
        cb = extractor.dispatch_callback(result.description)
        cb.update(result.description, 0, -1, workdir)

        cb.workspace_cleanup(workdir)
        self.arch = cb.arch

        if self.arch:
            caller.assumed_archs.append(self.arch)
        if not DEBUG:
            shutil.rmtree(temp_dir)

    def _skip_header(self, result, caller, workdir):
        desc = result.description.lower()
        if desc.startswith("xerox dlm firmware end of header"):
            caller.callnext = self._unpack_data
        # Skip the rest
        caller.skip = True

    def update(self, desc, off, size, workdir):
        if desc.lower().startswith("xerox dlm firmware start of header"):
            return self._skip_header

class HTML_CB(CALLBACK):
    def init(self):
        self.counter = 0

    def update(self, desc, off, size, workdir):
        self.counter += 1

class ELF_CB(CALLBACK):
    def init(self):
        self.seen_elf = 0
        self.max_elf = 1000

    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(off)
        data = fd.read(0x1000)  # read first page

        self.arch = self.checkasm(data)

        # if we see raw elfs, we probably met an unidentifiable filesystem
        if self.arch:
            if self.seen_elf == 0:
                fd.seek(0)
                data = fd.read()
                self.save(os.path.join(workdir, self.arch, "fs"), binwalk.core.compat.str2bytes(data))
            # Temporary use number of files to indicate arch possibility
            if self.seen_elf < self.max_elf:
                self.save(os.path.join(workdir, self.arch, "dummy"), b"")
                self.seen_elf += 1

class LINUXKERN_CB(CALLBACK):
    def update(self, desc, off, size, workdir):
        fd = binwalk.core.common.BlockFile(self.binfile)
        fd.seek(0)
        data = fd.read()

        self.arch = self.checkasm(data)

        if self.arch:
            self.save(os.path.join(workdir, self.arch, "kernel"), binwalk.core.compat.str2bytes(data))


import re
class Extractor(object):
    def __init__(self, binfile, toplevel="/data/firmware/images", recursion_level=0):
        self.toplevel = os.path.abspath(os.path.realpath(toplevel))
        self.binfile = os.path.abspath(os.path.realpath(binfile))
        self.skip = False
        self.callnext = None
        self.level = recursion_level

        self.lzma_cb = LZMA_CB(self.binfile, self.level)
        self.xz_cb = XZ_CB(self.binfile, self.level)
        self.squashfs_cb = SQUASHFS_CB(self.binfile, self.level)
        self.zip_cb = ZIP_CB(self.binfile, self.level)
        self.zlib_cb = ZLIB_CB(self.binfile, self.level)
        self.vxworks_cb = VXWORKS_CB(self.binfile, self.level)
        self.html_cb = HTML_CB(self.binfile, self.level)
        self.rar_cb = RAR_CB(self.binfile, self.level)
        self.gzip_cb = GZIP_CB(self.binfile, self.level)
        self.elf_cb = ELF_CB(self.binfile, self.level)
        self.bzip2_cb = BZIP2_CB(self.binfile, self.level)
        self.tar_cb = TAR_CB(self.binfile, self.level)
        self.linuxkern_cb = LINUXKERN_CB(self.binfile, self.level)
        self.xeroxdlm_cb = XEROXDLM_CB(self.binfile, self.level)
        self.cpio_cb = CPIO_CB(self.binfile, self.level)
        self.cramfs_cb = CRAMFS_CB(self.binfile, self.level)
        self.extfs_cb = EXTFS_CB(self.binfile, self.level)
        self.romfs_cb = ROMFS_CB(self.binfile, self.level)
        self.jffs2fs_cb = JFFS2FS_CB(self.binfile, self.level)
        self.ubifs_cb = UBIFS_CB(self.binfile, self.level)
        self.yaffs_cb = YAFFS_CB(self.binfile, self.level)
        self.dlromfs_cb = DLROMFS_CB(self.binfile, self.level)
        self.pfs_cb = PFS_CB(self.binfile, self.level)

    def dispatch_callback(self, desc):
        if desc.lower().startswith("lzma compressed data"):
            return self.lzma_cb
        elif desc.lower().startswith("xz compressed data"):
            return self.xz_cb
        elif desc.lower().startswith("squashfs filesystem"):
            return self.squashfs_cb
        elif desc.lower().startswith("zip archive data"):
            return self.zip_cb
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
        elif desc.lower().startswith("elf, "):
            return self.elf_cb
        elif desc.lower().startswith("bzip2 compressed data"):
            return self.bzip2_cb
        elif desc.lower().startswith("posix tar archive"):
            return self.tar_cb
        elif desc.lower().startswith("linux kernel version"):
            return self.linuxkern_cb
        elif desc.lower().startswith("xerox dlm firmware start of header"):
            return self.xeroxdlm_cb
        elif desc.lower().startswith("ascii cpio archive"):
            return self.cpio_cb
        elif desc.lower().startswith("cramfs filesystem"):
            return self.cramfs_cb
        elif desc.lower().startswith("linux ext filesystem"):
            return self.extfs_cb
        elif desc.lower().startswith("romfs filesystem"):
            return self.romfs_cb
        elif desc.lower().startswith("jffs2 filesystem"):
            return self.jffs2fs_cb
        elif desc.lower().startswith("ubifs filesystem superblock node"):
            return self.ubifs_cb
        elif desc.lower().startswith("yaffs filesystem"):
            return self.yaffs_cb
        elif desc.lower().startswith("d-link romfs filesystem"):
            return self.dlromfs_cb
        elif desc.lower().startswith("pfs filesystem"):
            return self.pfs_cb

        # failsafe
        return CALLBACK(self.binfile, self.level)


    def extract(self, workdir, extra_file_dir=True):
        temp_dir = make_tempdir('_binx')
        with binwalk.Modules(*[self.binfile], signature=True, quiet=True, log=os.path.join(temp_dir, LOGGING)) as mod:
            executed_mods = mod.execute()
            assert(len(executed_mods) == 1)
            sigmod = executed_mods[0]
            assert(isinstance(sigmod, binwalk.modules.Signature))

            self.assumed_archs = []
            for result in sigmod.results:
                if self.callnext:
                    self.callnext(result, self, temp_dir)
                if not self.skip and result.valid:
                    cb = self.dispatch_callback(result.description)
                    if DEBUG:
                        print("  "*self.level+f"{str(cb)}")
                    self.callnext = cb.update(result.description, result.offset, result.size, temp_dir)
                    if cb.arch:
                        self.assumed_archs.append(cb.arch)
                        if DEBUG:
                            print("  "*self.level+f"{cb.arch}")

        # special case, if we seen a lot html header/footer, that should be the firmware
        if self.html_cb.counter > 0:
            with open(self.binfile, 'rb') as fd:
                check_arch = CALLBACK(self.binfile, self.level).checkasm(fd.read())
            if check_arch:
                for i in range(self.html_cb.counter):
                    self.assumed_archs.append(check_arch)
                archpath = os.path.join(temp_dir, check_arch)
                if not os.path.exists(archpath):
                    os.mkdir(archpath)
                shutil.copy(self.binfile, archpath)
        if not self.assumed_archs:
            if not DEBUG:
                shutil.rmtree(temp_dir)
            return False

        toparch = max(self.assumed_archs, key=self.assumed_archs.count)
        possible_archs = set(arc for arc in self.assumed_archs
                                if self.assumed_archs.count(arc)==self.assumed_archs.count(toparch))
        arch = None
        for arc in possible_archs:
            if os.path.exists(os.path.join(temp_dir, arc)):
                arch = arc
                break
        if not arch:
            os.makedirs(os.path.join(temp_dir, toparch))
            arch = toparch

        rel_path = os.path.relpath(os.path.dirname(self.binfile), self.toplevel)
        dest_path = os.path.abspath(os.path.join(workdir, arch, rel_path))
        if extra_file_dir:
            dest_path = os.path.join(dest_path, os.path.basename(self.binfile))
        os.makedirs(dest_path, exist_ok=True)
        for fn in os.listdir(os.path.join(temp_dir, arch)):
            safe_filemove(os.path.join(temp_dir, arch, fn), os.path.join(dest_path, fn))

        if not DEBUG:
            shutil.rmtree(temp_dir)

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
                print(f"Unpack Failed: {fn}")
        except:
            traceback.print_exception(*sys.exc_info())
            print(f"Unpack Failed: {fn}")
            failed.append(fn)

    with open(FAIL_LOG, 'a') as fd:
        fd.write('\n'.join(failed) + '\n')

