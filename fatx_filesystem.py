import struct
import os
import logging

from datetime import datetime


# TODO: Perhaps get rid of this and just use datetime?
class FatXTimeStamp(object):
    """Holds a raw time stamp read directly from a FATX file system and converts to regular time units"""
    def __new__(cls, raw_val=0):
        """
        Args:
            raw_val (int): The raw integer read from the file system. Defaults to 0.
        """
        if cls is FatXTimeStamp:
            raise TypeError('Cannot instantiate FatXTimeStamp directly')

        return super(FatXTimeStamp, cls).__new__(cls)

    def __init__(self, raw_val=0):
        """
        Args:
            raw_val (int): The raw integer read from the file system. Defaults to 0.
        """
        self._time = raw_val
        self._year = self._month = self._day = self._hour = self._min = self._sec = None

    def __str__(self):
        return '{}/{}/{} {}:{:02d}:{:02d}'.format(
            self.month, self.day, self.year,
            self.hour, self.min, self.sec
        )

    @property
    def _log(self):
        return logging.getLogger('FATX.FileSystem.TimeStamp')

    @property
    def year(self):
        raise NotImplementedError

    @property
    def month(self):
        if not self._month:
            self._month = (self._time & 0x1E00000) >> 21
        return self._month

    @property
    def day(self):
        if not self._day:
            self._day = (self._time & 0x1F0000) >> 16
        return self._day

    @property
    def hour(self):
        if not self._hour:
            self._hour = (self._time & 0xF800) >> 11
        return self._hour

    @property
    def min(self):
        if not self._min:
            self._min = (self._time & 0x7E0) >> 5
        return self._min

    @property
    def sec(self):
        if not self._sec:
            self._sec = self._time & 0x1F
        return self._sec

    @property
    def is_valid(self):
        """Is this a valid date that makes sense?"""
        try:
            datetime(
                year=self.year,
                month=self.month,
                day=self.day,
                hour=self.hour,
                minute=self.min,
                second=self.sec
            )
        except ValueError:
            return False

        return True


class X360TimeStamp(FatXTimeStamp):
    """A FatXTimeStamp for Xbox 360."""
    @property
    def _log(self):
        return logging.getLogger('FATX.FileSystem.TimeStamp.X360')

    @property
    def year(self):
        """
        Returns (int):
            the year
        """
        if not self._year:
            self._year = ((self._time & 0xFE000000) >> 25) + 1980
        return self._year


class XTimeStamp(FatXTimeStamp):
    """A FatXTimeStamp for Xbox."""
    @property
    def _log(self):
        return logging.getLogger('FATX.FileSystem.TimeStamp.X')

    @property
    def year(self):
        """
        Returns (int):
            the year
        """
        if not self._year:
            self._year = ((self._time & 0xFE000000) >> 25) + 2000
        return self._year


FATX_SECTOR_SIZE    = 0x200
FATX_PAGE_SIZE      = 0x1000

FATX_SIGNATURE      = 0x58544146    # "FATX"
FATX_FILE_NAME_LEN  = 42

FILE_ATTRIBUTE_READONLY     = 0x00000001
FILE_ATTRIBUTE_HIDDEN       = 0x00000002
FILE_ATTRIBUTE_SYSTEM       = 0x00000004
FILE_ATTRIBUTE_DIRECTORY    = 0x00000010
FILE_ATTRIBUTE_ARCHIVE      = 0x00000020
FILE_ATTRIBUTE_DEVICE       = 0x00000040
FILE_ATTRIBUTE_NORMAL       = 0x00000080

DIRENT_NEVER_USED   = 0x00
DIRENT_DELETED      = 0xE5
DIRENT_NEVER_USED2  = 0xFF


class FatXDirent:
    def __init__(self, data, volume):
        (file_name_length,
         self.file_attributes,
         self.file_name,
         self.first_cluster,
         self.file_size,
         creation_time_i,
         last_write_time_i,
         last_access_time_i) = struct.unpack(volume.DIRENT_FORMAT, data)

        self.children = []
        self.parent = None
        self.volume = volume
        self.creation_time = None
        self.last_write_time = None
        self.last_access_time = None

        x360 = self.volume.endian_fmt == '>'
        ts = X360TimeStamp if x360 else XTimeStamp
        self.creation_time = ts(creation_time_i)
        self.last_write_time = ts(last_write_time_i)
        self.last_access_time = ts(last_access_time_i)
        self.deleted = file_name_length == DIRENT_DELETED

        if self.deleted:
            self.file_name = self.file_name.split('\xff')[0]
        elif file_name_length in (DIRENT_NEVER_USED, DIRENT_NEVER_USED):
            # TODO: I don't like that file_name is None means this is invalid. Perhaps we should raise an exception here
            #   and catch that? Perhaps TypeError
            self.file_name = None
        else:
            self.file_name = self.file_name[:file_name_length]

    @property
    def _log(self):
        return logging.getLogger('FATX.FileSystem.DirEnt')

    @classmethod
    def from_file(cls, f, volume):
        data = f.read(0x40)
        return cls(data, volume)

    def add_dirent_stream_to_this_directory(self, stream):
        if not self.is_directory:
            raise Exception("This dirent is not a directory!")

        for dirent in stream:
            dirent.parent = self
            self.children.append(dirent)

    @property
    def is_file(self):
        return not self.is_directory

    @property
    def is_directory(self):
        return bool(self.file_attributes & FILE_ATTRIBUTE_DIRECTORY)

    ###########################################
    # TODO: need to move these to FatXVolume
    # TODO: support files marked as deleted
    def _write_file(self, path):
        fat = self.volume.file_allocation_table
        cluster = self.first_cluster
        buffer = ''
        while True:
            buffer += self.volume.read_cluster(cluster)
            if cluster >= (0xfff0 if self.volume.fat16x else 0xfffffff0):
                break
            cluster = fat[cluster]

        f = open(path, 'wb')
        f.write(buffer[:self.file_size])
        f.close()

    def write(self, path):
        if self.is_directory:
            if not os.path.exists(path):
                os.makedirs(path)
        else:
            self._write_file(path)

    def recover(self, path, undelete=False):
        """ Recover legitimately using the FAT. """
        if self.deleted and not undelete:
            return
        whole_path = path + '/' + self.file_name
        # print attributes (dir/file/del)
        if self.is_directory:
            prefix = 'DIR  '
        else:
            prefix = 'FILE '
        if self.deleted:
            prefix = 'DEL  '
        self._log.debug('%s', prefix + whole_path)
        if self.is_directory:
            # create directory
            self.write(whole_path)
            for dirent in self.children:
                dirent.recover(whole_path, undelete)
        else:
            self.write(whole_path)
            # dump regular file
    ###########################################

    def format_attributes(self):
        attributes = ''

        if self.file_attributes & FILE_ATTRIBUTE_READONLY:
            attributes += 'READONLY '
        if self.file_attributes & FILE_ATTRIBUTE_HIDDEN:
            attributes += 'HIDDEN '
        if self.file_attributes & FILE_ATTRIBUTE_SYSTEM:
            attributes += 'SYSTEM '
        if self.file_attributes & FILE_ATTRIBUTE_DIRECTORY:
            attributes += 'DIRECTORY '
        if self.file_attributes & FILE_ATTRIBUTE_ARCHIVE:
            attributes += 'ARCHIVE '
        if self.file_attributes & FILE_ATTRIBUTE_DEVICE:
            attributes += 'DEVICE '
        if self.file_attributes & FILE_ATTRIBUTE_NORMAL:
            attributes += 'NORMAL '

        return attributes

    def print_dirent(self, root_path):
        if self.deleted:
            return

        if self.is_directory:
            prefix = 'DIR  '
        else:
            prefix = 'FILE '

        whole_path = root_path + '/' + self.file_name
        self._log.debug('%s', prefix + whole_path)
        if self.is_directory:
            for child in self.children:
                child.print_dirent(whole_path)

    def print_fields(self):
        def print_aligned(header, value):
            self._log.critical('%-26s %s', header, value)

        print_aligned("FileNameLength:", DIRENT_DELETED if self.deleted else len(self.file_name))
        print_aligned("FileName:", self.file_name)
        print_aligned("FileSize:", '0x{:x} bytes'.format(self.file_size))
        print_aligned("FileAttributes:", self.format_attributes())
        print_aligned("FirstCluster", self.first_cluster)
        print_aligned("CreationTime:", str(self.creation_time))
        print_aligned("LastWriteTime:", str(self.last_write_time))
        print_aligned("LastAccessTime:", str(self.last_access_time))


class FatXVolume(object):
    def __init__(self, f, offset, length, endian):
        self.infile = f
        self.offset = offset
        self.length = length
        self.endian_fmt = endian
        self.FATX_FORMAT = self.endian_fmt + 'LLLL'
        self.DIRENT_FORMAT = self.endian_fmt + 'BB42sLLLLL'
        self.file_allocation_table = []
        self._root = []
        self.signature = self.serial_number = self.sectors_per_cluster = self.root_dir_first_cluster = \
            self.bytes_per_cluster = self.max_clusters = self.fat_byte_offset = self.file_area_byte_offset = 0
        self.fat16x = False

    @property
    def _log(self):
        return logging.getLogger('FATX.FileSystem.Volume')

    def mount(self):
        self._log.info('Mounting volume at 0x%X (length=0x%X)', self.offset, self.length)

        # read volume metadata
        self.read_volume_metadata()

        # calculate file allocation and file area offsets
        self.calculate_offsets()

        # get file allocation table (int[])
        self.file_allocation_table = self.read_file_allocation_table()

        self._root = self.read_directory_stream(
            self.cluster_to_physical_offset(self.root_dir_first_cluster))

        # for each dirent in root, populate children
        self.populate_dirent_stream(self._root)

    def get_root(self):
        return self._root

    def seek_file_area(self, offset, whence=0):
        """ Seek relative to file_area_byte_offset """
        offset += self.file_area_byte_offset + self.offset
        self.infile.seek(offset, whence)

    def read_file_area(self, size):
        return self.infile.read(size)

    def read_cluster(self, cluster):
        self.infile.seek(self.cluster_to_physical_offset(cluster))
        return self.infile.read(self.bytes_per_cluster)

    def seek_to_cluster(self, cluster):
        self.infile.seek(self.cluster_to_physical_offset(cluster))

    def byte_offset_to_cluster(self, offset):
        return (offset / self.bytes_per_cluster) + 1

    def byte_offset_to_physical_offset(self, offset):
        return self.offset + offset

    def cluster_to_physical_offset(self, cluster):
        return (self.offset +
                self.file_area_byte_offset +
                (self.bytes_per_cluster * (cluster - 1)))

    def read_volume_metadata(self):
        self.infile.seek(self.offset)

        (self.signature,
         self.serial_number,
         self.sectors_per_cluster,
         self.root_dir_first_cluster) = struct.unpack(self.FATX_FORMAT,
                                                      self.infile.read(struct.calcsize(self.FATX_FORMAT)))

        self._log.debug('Volume serial number: 0x%X', self.serial_number)

        # TODO: Remove this in order to handle corrupted metadata
        if self.signature != FATX_SIGNATURE:
            raise ValueError("Invalid FATX signature!")

    def get_cluster_chain(self, cluster_map):
        buffer = ''
        for cluster in cluster_map:
            buffer += self.read_cluster(cluster)
        return buffer

    def get_cluster_chain_map(self, first_cluster):
        chain = []
        cluster = first_cluster
        max_cluster = (0xfff0 if self.fat16x else 0xfffffff0)
        while self.file_allocation_table[cluster] <= max_cluster:
            chain.append(self.file_allocation_table[cluster])
        return chain

    def read_file_allocation_table(self):
        def construct_fat_format(num_clusters):
            return self.endian_fmt + (('H' if self.fat16x else 'L') * num_clusters)

        fat_offset = self.byte_offset_to_physical_offset(self.fat_byte_offset)
        self.infile.seek(fat_offset)
        fat_format = construct_fat_format(self.max_clusters)
        fat_length = struct.calcsize(fat_format)
        fat_table = self.infile.read(fat_length)
        return [entry for entry in struct.unpack(fat_format, fat_table)]

    def calculate_offsets(self):
        # reserved for volume metadata
        reserved_bytes = 0x1000

        # most commonly 0x4000
        self.bytes_per_cluster = self.sectors_per_cluster * FATX_SECTOR_SIZE
        
        self.max_clusters = (self.length / self.bytes_per_cluster) + 1  # +1 is reserved_fat_entries
        if self.max_clusters < 0xfff0:
            bytes_per_fat = self.max_clusters * 2
            self.fat16x = True
        else:
            bytes_per_fat = self.max_clusters * 4
            self.fat16x = False

        # align to nearest page
        bytes_per_fat = (bytes_per_fat + (FATX_PAGE_SIZE - 1)) & ~(FATX_PAGE_SIZE - 1)

        # offset of file allocation table
        self.fat_byte_offset = reserved_bytes
        # offset of file area
        self.file_area_byte_offset = self.fat_byte_offset + bytes_per_fat

    def populate_dirent_stream(self, stream):
        for dirent in stream:
            if dirent.is_directory and not dirent.deleted: # dirent stream is not guaranteed!
                # TODO: don't do this with first_cluster... read from FAT!
                dirent_stream = self.read_directory_stream( 
                    self.cluster_to_physical_offset(dirent.first_cluster))

                dirent.add_dirent_stream_to_this_directory(dirent_stream)

                self.populate_dirent_stream(dirent_stream)

    def read_directory_stream(self, offset):
        stream = []

        self.infile.seek(offset)
        for _ in range(256):
            dirent = FatXDirent.from_file(self.infile, self)

            # check for end of dirent stream
            if dirent.file_name is None:
                break

            stream.append(dirent)

        return stream

    def print_volume_metadata(self):
        def print_aligned(header, value):
            self._log.critical("%-26s %s", header, value)

        print_aligned("Signature:", self.signature)
        print_aligned("SerialNumber:", self.serial_number)
        print_aligned("SectorsPerCluster:", "{} (0x{:x} bytes)".format(
            self.sectors_per_cluster, self.sectors_per_cluster * FATX_SECTOR_SIZE))
        print_aligned('RootDirFirstCluster:', self.root_dir_first_cluster)
        self._log.critical('')

        print_aligned("Calculated Offsets:", '')
        print_aligned("PartitionOffset:", "0x{:x}".format(self.offset))
        print_aligned("FatByteOffset:", "0x{:x} (+0x{:x})".format(
            self.byte_offset_to_physical_offset(self.fat_byte_offset), self.fat_byte_offset))
        print_aligned("FileAreaByteOffset:", "0x{:x} (+0x{:x})".format(
            self.byte_offset_to_physical_offset(self.file_area_byte_offset), self.file_area_byte_offset))
        self._log.critical('')
