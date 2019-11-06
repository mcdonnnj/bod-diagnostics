#!/usr/bin/env python

"""bod-diagnostics provides diagnostic information from BOD report CSVs.

Usage:
    bod-diagnostics (--https | --trustymail) [--debug] <csv-file> [DOMAIN ...]
    bod-diagnostics -h | -v

Arguments:
    csv-file  The CSV file to parse
    DOMAIN    An optional list of domains to filter against

Options:
    --https       Parse results for an https report
    --trustymail  Parse results for a trustymail report
    --debug       Print debug output
    -h --help     Show this help message and exit
    -v --version  Show version and exit

"""

import csv
import logging

import docopt

from ._version import __version__
from .report_parsers import HTTPSReport, TrustymailReport


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
            parser = None
            if args["--https"]:
                logging.debug("Providing https diagnostics.")
                parser = HTTPSReport(args["DOMAIN"])
            elif args["--trustymail"]:
                logging.debug("Providing trustymail diagnostics.")
                parser = TrustymailReport(args["DOMAIN"])

            csv_reader = csv.DictReader(f)
            for row in csv_reader:
                parser.parse_row(row)
            parser.output_results()
    except Exception as err:
        logging.error(
            f"Problem parsing provided CSV file '{args['<csv-file>']}': {err}"
        )
