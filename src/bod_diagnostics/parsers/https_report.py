"""
Module to provide BOD failure info for HTTPS reports.

This module is designed to take the pshttself.__results.csv file for a given
organization's report and provide more granular information about why domains
are failing.
"""

import logging

from . import _utils


class HTTPSReport:
    """Class to analyze a pshtt produced HTTPS report for errors."""

    def __init__(self, domains=None):
        """Set up internal variables."""
        self.__domains = domains if domains else []
        self.__domains = [domain.lower() for domain in self.__domains]
        logging.debug(f"Domains provided: {self.__domains}")

        self.__results = {}

    def __output_domain_results(domain, results):
        """Print the results for a domain in an informational manner."""
        bod_failed = False
        print(f"Domain: {domain}")
        if "Live" in results:
            print(f"\tLive : {results['Live']}")
            print(
                f"\tBase Domain HSTS Preloaded : {results['Base Domain HSTS Preloaded']}"
            )
        for key in (
            "Domain Supports HTTPS",
            "Domain Enforces HTTPS",
            "Domain Uses Strong HSTS",
        ):
            if key in results:
                bod_failed = True
                print(f"\t{key} : {results[key]}")
                print("\t\tCalculated by")
                print(f"\t\t'{key}' or ('Live' and 'Base Domain HSTS Preloaded')")
        if bod_failed:
            print("\tBOD 18-01 Web Compliance Calculated by")
            print(
                "\t('Domain Supports HTTPS' and 'Domain Enforces HTTPS' and 'Domain Uses Strong HSTS')"
            )
            print("\t or ('Live'")
            print("\t     and ('Base Domain HSTS Preloaded'")
            print(
                "\t          or (not 'HTTPS Full Connection' and 'HTTPS Client Auth Required')"
            )
            print("\t         )")
            print("\t    }")
        if "Domain Uses Weak Crypto" in results:
            print("\tThe Following Weak Crypto Algorithms Are Supported:")
            print(f"\t{results['Domain Uses Weak Crypto']}")

    def output_results(self):
        """Print the results of analysis."""
        for k, v in self.__results.items():
            if v:
                self.__output_domain_results(k, v)

    def parse_row(self, csv_row):
        """Parse a provided CSV file to provide pshtt diagnostic information."""
        # If we specified domains we check to see if this is one we want
        if self.__domains:
            if csv_row["Domain"].lower() not in self.__domains:
                return

        csv_row = _utils.convert_booleans(csv_row)

        domain_fallback_check = (
            csv_row["Live"] and csv_row["Base Domain HSTS Preloaded"]
        )

        domain_uses_https = csv_row["Domain Supports HTTPS"] or domain_fallback_check
        domain_enforces_https = (
            csv_row["Domain Enforces HTTPS"] or domain_fallback_check
        )
        domain_uses_strong_hsts = (
            csv_row["Domain Uses Strong HSTS"] or domain_fallback_check
        )
        domain_uses_weak_crypto = csv_row["Domain Supports Weak Crypto"]

        self.__results[csv_row["Domain"].lower()] = {}
        if not (
            domain_uses_https and domain_enforces_https and domain_uses_strong_hsts
        ):
            self.__results[csv_row["Domain"].lower()]["Live"] = csv_row["Live"]
            self.__results[csv_row["Domain"].lower()][
                "Base Domain HSTS Preloaded"
            ] = csv_row["Base Domain HSTS Preloaded"]

            if not domain_uses_https:
                self.__results[csv_row["Domain"].lower()][
                    "Domain Supports HTTPS"
                ] = csv_row["Domain Supports HTTPS"]
            if not domain_enforces_https:
                self.__results[csv_row["Domain"].lower()][
                    "Domain Enforces HTTPS"
                ] = csv_row["Domain Enforces HTTPS"]
            if not domain_uses_strong_hsts:
                self.__results[csv_row["Domain"].lower()][
                    "Domain Uses Strong HSTS"
                ] = csv_row["Domain Uses Strong HSTS"]

        if domain_uses_weak_crypto:
            self.__results[csv_row["Domain"].lower()][
                "Domain Uses Weak Crypto"
            ] = csv_row["Web Hosts With Weak Crypto"]
