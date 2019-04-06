from fatx_drive import FatXDrive
from fatx_signatures import *

xog_signatures = [XBESignature, PDBSignature]


class XOGDrive(FatXDrive):
    BYTEORDER = '<'

    def __init__(self, f):
        super(XOGDrive, self).__init__(f)

        self.add_partition(0x80000, 0x2ee00000)       # CACHE
        self.add_partition(0x2EE80000, 0x2ee00000)    # CACHE
        self.add_partition(0x5DC80000, 0x2ee00000)    # CACHE
        self.add_partition(0x8CA80000, 0x1f400000)    # SHELL
        self.add_partition(0xABE80000, 0x1312D6000)   # DATA
