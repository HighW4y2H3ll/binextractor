"""
    Initial Code comes from binwalk/plugins/unpfs.py
"""

import os
import sys
import errno
import struct

if sys.modules['binwalk']:
    binwalk = sys.modules['binwalk']
else:
    CUR_DIR = os.path.abspath(os.path.realpath(os.path.dirname(__file__)))
    BINWALK_DIR = os.path.join(CUR_DIR, 'binwalk/src/binwalk')
    _binwalk_init = os.path.join(BINWALK_DIR, "__init__.py")
    _binwalk_spec = importlib.util.spec_from_file_location('binwalk', _binwalk_init)
    binwalk = importlib.util.module_from_spec(_binwalk_spec)
    sys.modules[_binwalk_spec.name] = binwalk
    _binwalk_spec.loader.exec_module(binwalk)

class PFSCommon(object):

    def _make_short(self, data, endianness):
        """Returns a 2 byte integer."""
        data = binwalk.core.compat.str2bytes(data)
        return struct.unpack('%sH' % endianness, data)[0]

    def _make_int(self, data, endianness):
        """Returns a 4 byte integer."""
        data = binwalk.core.compat.str2bytes(data)
        return struct.unpack('%sI' % endianness, data)[0]

class PFS(PFSCommon):
    """Class for accessing PFS meta-data."""
    HEADER_SIZE = 16

    def __init__(self, fname, endianness='<'):
        self.endianness = endianness
        self.meta = binwalk.core.common.BlockFile(fname, 'rb')
        header = self.meta.read(self.HEADER_SIZE)
        self.file_list_start = self.meta.tell()

        self.num_files = self._make_short(header[-2:], endianness)
        self.node_size = self._get_fname_len() + 12

    def _get_fname_len(self, bufflen=128):
        """Returns the number of bytes designated for the filename."""
        buff = self.meta.peek(bufflen)
        strlen = buff.find('\0')
        for i, b in enumerate(buff[strlen:]):
            if b != '\0':
                return strlen+i
        return bufflen

    def _get_node(self):
        """Reads a chunk of meta data from file and returns a PFSNode."""
        data = self.meta.read(self.node_size)
        return PFSNode(data, self.endianness)

    def get_end_of_meta_data(self):
        """Returns integer indicating the end of the file system meta data."""
        return self.HEADER_SIZE + self.node_size * self.num_files

    def entries(self):
        """Returns file meta-data entries one by one."""
        self.meta.seek(self.file_list_start)
        for i in range(0, self.num_files):
            yield self._get_node()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.meta.close()

class PFSNode(PFSCommon):
    """A node in the PFS Filesystem containing meta-data about a single file."""

    def __init__(self, data, endianness):
        self.fname, data = data[:-12], data[-12:]
        self._decode_fname()
        self.inode_no = self._make_int(data[:4], endianness)
        self.foffset = self._make_int(data[4:8], endianness)
        self.fsize = self._make_int(data[8:], endianness)

    def _decode_fname(self):
        """Extracts the actual string from the available bytes."""
        self.fname = self.fname[:self.fname.find('\0')]
        self.fname = self.fname.replace('\\', '/')
