from fatx_filesystem import FatXVolume
import logging

LOG = logging.getLogger('FATX.Drive')


class FatXDrive(object):
    """A FATX drive."""

    def __init__(self, f):
        self.file = f
        self.partitions = []

        f.seek(0, 2)
        self.length = f.tell()
        f.seek(0, 0)

    def add_partition(self, offset, length):
        self.partitions.append(FatXVolume(self.file, offset, length, self.BYTEORDER))

    def get_partition(self, index):
        return self.partitions[index-1]

    def print_partitions(self):
        LOG.critical("%-6s %-18s %s", "Index", "Offset", "Length")
        for i, partition in enumerate(self.partitions):
            LOG.critical("%-6s 0x%-16x 0x%x", i + 1, partition.offset, partition.length)
        LOG.critical('')
