#!/usr/bin/env python

"""bod-diagnostics provides diagnostic information from BOD report CSVs.

Usage:
    bod-diagnostics (--pshtt | --trustymail) [--debug] <csv-file> [DOMAIN ...]
    bod-diagnostics -h | -v

Arguments:
    csv-file  The CSV file to parse
    DOMAIN    An optional list of domains to filter against

Options:
    --pshtt       Parse results for a pshtt report
    --trustymail  Parse results for a trustymail report
    --debug       Print debug output
    -h --help     Show this help message and exit
    -v --version  Show version and exit

"""

import logging

import docopt

from . import pshtt
from . import trustymail
from ._version import __version__


def setup_logging(debug=False):
    """Set logging level to debug if desired, otherwise set it to warning."""
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING

    logging.basicConfig(format="%(message)s", level=log_level)


def main():
    """Provide a command line front end to the diagnostic libraries."""
    args = docopt.docopt(__doc__, version=__version__)
    setup_logging(args["--debug"])

    try:
        with open(args["<csv-file>"], "r") as f:
            if args["--pshtt"]:
                logging.debug("Providing pshtt diagnostics.")
                pshtt.parse_csv(f, args["DOMAIN"])
            elif args["--trustymail"]:
                logging.debug("Providing trustymail diagnostics.")
                trustymail.parse_csv(f, args["DOMAIN"])
    except Exception as err:
        logging.error(
            f"Problem parsing provided CSV file '{args['<csv-file>']}': {err}"
        )
