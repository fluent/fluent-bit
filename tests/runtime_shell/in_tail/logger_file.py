#!/bin/env python

import sys
import uuid
import time
import signal
import logging
from argparse import ArgumentParser
from logging.handlers import RotatingFileHandler
from threading import Thread

class LoggerManager:
    def __init__(self, args):
        # KB to bytes
        self.max_bytes = (args.size * 1000)
        self.backup = args.backup
        self.lines = args.lines
        self.delay = args.delay
        self.threads = []

        # Create a thread for every writer
        for f in args.filenames:
            thread = Thread(target = self.single_logger_thread, args = (f,))
            if thread is None:
                print("error creating thread")
                sys.exit(1)
            self.threads.append(thread)
            thread.start()
            print("Logger thread for '" +  f + "' has started")

        for th in self.threads:
            th.join()
            print("Logger thread finished")

    def single_logger_thread(self, name):
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        handler = RotatingFileHandler(name, maxBytes = self.max_bytes,
                                      backupCount = self.backup)
        logger.addHandler(handler)
        rnd = uuid.uuid4()

        i = 0
        while i < self.lines:
            logger.debug(rnd)
            if self.delay > 0.0:
                time.sleep(self.delay / 1000.0)
            i = i + 1

def signal_handler(sig, frame):
    print("stopping logger")
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)

    # Define arguments
    parser = ArgumentParser()
    parser.add_argument("-b", "--backup", dest="backup", default=50, type=int)
    parser.add_argument("-d", "--delay", dest="delay", default=0.1, type=float,
                        help="milliseconds delay between line writes")
    parser.add_argument("-l", "--lines", dest="lines", default=1000, type=int)
    parser.add_argument("-f", "--file", dest="filenames", action='append', required=True,
                        help="write logs to FILE", metavar="FILE")
    parser.add_argument("-s", "--size", dest="size", type=int,
                        help="maximum log file size in KB before rotation",
                        default=256)
    # Read arguments
    args = parser.parse_args()

    # Start the Logger
    lm = LoggerManager(args)
