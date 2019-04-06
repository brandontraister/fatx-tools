#!/usr/bin/python

import argparse
import os
import logging
import sys

from fatx_x360 import X360Drive, x360_signatures
from fatx_xog import XOGDrive, xog_signatures
from fatx_analyzer import FatXAnalyzer

MODE_XBOG = 0
MODE_X360 = 1

LOG = logging.getLogger('FATX')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Xbox 360 and Xbox Original drive utilities.")

    # TODO: Make this a positional arg with 1 or more values
    parser.add_argument("-i", "--inputfile", help="Input image file.", required=True)
    parser.add_argument("-o", "--outputpath", help="Path to write recovered files.")
    parser.add_argument("-n", "--index", help="Partition index.", type=int)

    # TODO: Get rid of mode and autodetect
    parser.add_argument("-m", "--mode", help="Xbox mode (0=Xbox Original, 1=Xbox 360)", type=int, required=True)
    parser.add_argument("-d", "--print-drive", help="Print drive partitions.", action='store_true')
    parser.add_argument("-f", "--print-files", help="Print files in partition.", action='store_true')
    parser.add_argument("-p", "--print-partition", help="Print partition volume metadata.", action='store_true')
    parser.add_argument("-r", "--recover", help="Recover files.", action="store_true")
    parser.add_argument("-u", "--undelete", help="Recover files marked as deleted.", action="store_true")

    parser.add_argument('-v', '--verbosity', help='The log verbosity', type=str, default='NOTSET')

    parser.add_argument("-so", "--scan-orphans", help="Use orphan scanner.", action="store_true")
    parser.add_argument("-son", "--so-length", help="Number of clusters to search through.",
                        type=lambda x: int(x, 0), default=0)

    parser.add_argument("-ss", "--scan-signatures", help="Use signature scanner.", action="store_true")
    parser.add_argument("-ssx", "--ss-interval", help="Interval for finding signatures (default is 0x200).",
                        type=lambda x: int(x, 0), default=0x1000)
    parser.add_argument("-ssl", "--ss-length", help="Maximum amount of data to search through.",
                        type=lambda x: int(x, 0), default=0)

    args = parser.parse_args()

    # region Setup the logger
    log_verbosity = [v for k, v in logging.__dict__.items() if k.startswith(args.verbosity.upper())][0]

    # Console output. Only put info and above in the console.
    _stream = logging.StreamHandler(sys.stdout)
    _stream.setLevel(logging.INFO)
    _stream.setFormatter(logging.Formatter('%(levelname).4s: %(message)s'))

    if log_verbosity != logging.NOTSET:
        # Did we specify a verbosity? The user must be serious about logging. Lets log everything to a file too,
        #   including debug if the level is set to debug.
        _file = logging.FileHandler('fatx.log')
        _file.setLevel(logging.DEBUG)
        _file.setFormatter(
            logging.Formatter('%(module)s::%(funcName)s::%(lineno)d %(levelname).4s %(asctime)s - %(message)s'))
        LOG.setLevel(log_verbosity)
        LOG.addHandler(_file)
    else:
        LOG.setLevel(logging.INFO)

    LOG.addHandler(_stream)
    # endregion

    # TODO: have the option to specify a custom range
    with open(args.inputfile, 'rb') as infile:
        drive = None

        # choose a drive
        if args.mode == MODE_XBOG:
            drive = XOGDrive(infile)
        elif args.mode == MODE_X360:
            drive = X360Drive(infile)

        if args.print_drive:
            LOG.critical("Partitions:")
            drive.print_partitions()

        if args.print_files or args.print_partition or args.recover or args.scan_orphans or args.scan_signatures:
            if not args.index:
                raise Exception("Must specify a partition index in order to print its contents (--index).")

            fatx = drive.get_partition(args.index)
            fatx.mount()
            analyzer = FatXAnalyzer(fatx)

            if args.print_partition:
                fatx.print_volume_metadata()

            if args.print_files or args.recover:
                root_dir = fatx.get_root()

                if len(root_dir) == 0:
                    LOG.error("No files in this partition!")
                else:
                    if args.print_files:
                        for dirent in root_dir:
                            dirent.print_dirent("root:")
                    if args.recover:
                        if not args.outputpath:
                            raise Exception("Must specify an output path (--output).")

                        if not os.path.exists(args.outputpath):
                            os.makedirs(args.outputpath)

                        for dirent in root_dir:
                            dirent.recover(args.outputpath, args.undelete)

            # orphan scanner will look for anything that looks
            # like a valid DIRENT entry for complete file info
            if args.scan_orphans:
                if args.recover and not args.outputpath:
                    raise Exception("Must supply output path if recovering files! (--outputpath)")

                analyzer.perform_orphan_analysis(max_clusters=args.so_length)
                roots = analyzer.get_roots()
                for root in roots:
                    root.print_dirent('.')

                if args.recover:
                    for root in roots:
                        root.rescue(args.outputpath)

            # signature scanner will go through blocks of data
            # testing various signatures to see if they match
            if args.scan_signatures:
                if args.recover and not args.outputpath:
                    raise Exception("Must supply output path if recovering files! (--outputpath)")

                if args.mode == MODE_XBOG:
                    analyzer.perform_signature_analysis(xog_signatures,
                                                        interval=args.ss_interval,
                                                        length=args.ss_length)
                elif args.mode == MODE_X360:
                    analyzer.perform_signature_analysis(x360_signatures,
                                                        interval=args.ss_interval,
                                                        length=args.ss_length)

                if args.recover:
                    for find in analyzer.found_signatures:
                        find.recover(args.outputpath)
