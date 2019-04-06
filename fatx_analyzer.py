from __future__ import print_function
import time
import os
import string
import logging

from multiprocessing.pool import ThreadPool

from fatx_filesystem import (FatXDirent,
                             DIRENT_DELETED, DIRENT_NEVER_USED,
                             DIRENT_NEVER_USED2, FATX_FILE_NAME_LEN)

__all__ = ['FatXOrphan', 'FatXAnalyzer']

VALID_CHARS = set(string.ascii_letters + string.digits + '!#$%&\'()-.@[]^_`{}~ ')
LOG = logging.getLogger('FATX.Analyzer')


class LimitedThreadPool(ThreadPool):
    """
    A ThreadPool that will block on apply_async if there are too many items in the queue.

    This is to avoid putting a 250GB file in the queue.
    """
    def apply_async(self, *args, **kwargs):
        ignore_limits = False
        if 'ignore_limits' in kwargs:
            ignore_limits = kwargs.pop('ignore_limits')
        if not ignore_limits:
            while self._inqueue.qsize() > 100:
                time.sleep(5)
        super(LimitedThreadPool, self).apply_async(*args, **kwargs)


class FatXOrphan(FatXDirent):
    """ An orphaned directory entry. """

    def __init__(self, data, volume):
        super(FatXOrphan, self).__init__(data, volume)
        self.cluster = None

    @property
    # @profile
    def is_valid(self):
        """ Checks if this recovered dirent is actually valid. """
        if self.file_name is None:
            return False

        name_len = DIRENT_DELETED if self.deleted else len(self.file_name)

        # FILE or DIR
        if (self.file_attributes != 0x00 and
                self.file_attributes != 0x10):
            return False

        # validate file name length
        if (name_len not in (DIRENT_DELETED, DIRENT_NEVER_USED2)
                and name_len > FATX_FILE_NAME_LEN):
            return False

        # check if it points outside of the partition
        if self.first_cluster > self.volume.max_clusters:
            return False

        # validate file name
        if not all(c in VALID_CHARS for c in self.file_name):
            return False

        # validate file time stamps
        if (not self.creation_time.is_valid or
                not self.last_write_time.is_valid or
                not self.last_access_time.is_valid):
            return False

        return True

    def add_child(self, child):
        """ This child belongs to this dirent. """
        if self.is_file:
            raise Exception("Only directories can have children!")

        self.children.append(child)

    def set_parent(self, parent):
        """ This dirent belongs to this parent dirent. """
        self.parent = parent

    def set_cluster(self, cluster):
        """ This dirent belongs to this cluster. """
        self.cluster = cluster

    def rescue(self, path):
        """ This dumps without relying on the FAT. """
        whole_path = path + '/' + self.file_name
        self.volume.seek_to_cluster(self.first_cluster)
        LOG.info('Recovering: %r', whole_path)
        if self.is_directory():
            if not os.path.exists(whole_path):
                try:
                    os.makedirs(whole_path)
                except (OSError, IOError):
                    LOG.exception('Failed to create directory: %s', whole_path)
                    return
            for dirent in self.children:
                dirent.rescue(whole_path)
        else:
            try:
                with open(whole_path, 'wb') as f:
                    f.write(self.volume.infile.read(self.file_size))
            except (OSError, IOError):
                LOG.exception('Failed to create file: %s', whole_path)


class FatXAnalyzer:
    """ Analyzes a FatX partition for deleted files. """
    def __init__(self, volume):
        self.volume = volume
        self.roots = []      # List[FatXOrphan]
        self.orphanage = []  # List[FatXOrphan]
        self.current_block = 0
        self.found_signatures = []

    # TODO: add constructor for finding files with corrupted FatX volume metadata
    def get_orphanage(self):
        """ Orphanage contains the list of orphaned dirents. """
        return self.orphanage

    def get_roots(self):
        """ Roots contains a list of linked orphans. """
        return self.roots

    def get_valid_sigs(self):
        """ List of found signatures. """
        return self.found_signatures

    def perform_signature_analysis(self, signatures, interval=0x200, length=0):
        """ Searches for file signatures. """
        LOG.info('signature analysis has begun...')
        # Lets be reasonable
        # BYTE_SIZE    = 0x1     # very slow, you must be desperate?
        # SECTOR_SIZE  = 0x200   # slow, very effective
        # PAGE_SIZE    = 0x1000  # moderate speed, less effective
        # CLUSTER_SIZE = 0x4000  # high speed, least effective
        if interval not in (1, 0x200, 0x1000, 0x4000):
            return ValueError("Valid intervals are 1, 0x20, 0x1000, or 0x4000.")

        if length == 0 or length > self.volume.length:
            length = self.volume.length

        time0 = time.time()
        self.found_signatures = []
        for index in range(length // interval):
            self.current_block = index
            offset = index * interval
            for signature in signatures:
                test = signature(offset, self.volume)
                self.volume.seek_file_area(offset)
                if test.test():
                    test.parse()
                    self.found_signatures.append(test)
                    LOG.debug('%s', test)
        time1 = time.time()
        LOG.info('analysis finished in %s', time1 - time0)

    def perform_orphan_analysis(self, max_clusters=0):
        """ Searches for FatXDirent structures. """
        LOG.info('orphan analysis has begun...')
        time0 = time.time()
        self.recover_orphans(max_clusters)
        time1 = time.time()
        LOG.info('analysis finished in %s seconds. Linking orphans...', time1 - time0)

        # give them a home
        self.link_orphans()
        LOG.info('and done. :)')

    # TODO: optimize file reading
    def recover_orphans(self, max_clusters=0):
        """ Begin search for orphaned dirents. """
        orphans = []
        if (max_clusters > self.volume.max_clusters or
                max_clusters == 0):
            max_clusters = self.volume.max_clusters

        def read_cluster(i, data):
            self.current_block = max(self.current_block, i)

            for x in range(256):
                offset = x * 0x40

                # Optimization: Don't bother reading if file_name_length
                # is DIRENT_NEVER_USED or DIRENT_NEVER_USED2
                # Also avoid 1 character file_name_length
                if data[offset] in ('\x00', '\x01', '\xff'):
                    continue

                dirent = FatXOrphan(data[offset:offset+0x40], self.volume)

                if dirent.is_valid:
                    dirent.set_cluster(cluster)
                    orphans.append(dirent)

        tp = LimitedThreadPool()

        for cluster in range(1, max_clusters):
            tp.apply_async(read_cluster, args=(cluster, self.volume.read_cluster(cluster)))

        tp.close()
        tp.join()

        self.orphanage = orphans

    def find_children(self, parent):
        """ Find children for this directory. """
        for orphan in self.orphanage:
            if orphan.cluster == parent.first_cluster:
                parent.add_child(orphan)
                orphan.set_parent(parent)

    def link_orphans(self):
        """ Link parent directories with their children. """
        for orphan in self.orphanage:
            if orphan.is_directory:
                self.find_children(orphan)

        # find root directories
        for orphan in self.orphanage:
            if orphan.parent is None:
                self.roots.append(orphan)
