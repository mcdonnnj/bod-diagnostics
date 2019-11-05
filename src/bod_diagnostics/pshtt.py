"""
Module to provide BOD failure info for HTTPS reports.

This module is designed to take the pshtt-results.csv file for a given
organization's report and provide more granular information about why domains
are failing.
"""

import csv
import logging

from . import utils


def output_domain_results(domain, results):
    """Print the results of analysis in an informational manner."""
    bod_failed = False
    print(f"Domain: {domain}")
    if "Live" in results:
        print(f"\tLive : {results['Live']}")
        print(f"\tBase Domain HSTS Preloaded : {results['Base Domain HSTS Preloaded']}")
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


def parse_csv(csv_file, domains=None):
    """Parse a provided CSV file to provide pshtt diagnostic information."""
    if domains:
        domains = [domain.lower() for domain in domains]
    logging.debug(f"Domains provided: {domains}")

    results = {}

    csv_reader = csv.DictReader(csv_file)
    for row in csv_reader:
        # If we specified domains we check to see if this is one we want
        if domains:
            if row["Domain"].lower() not in domains:
                continue

        row = utils.convert_booleans(row)

        domain_fallback_check = row["Live"] and row["Base Domain HSTS Preloaded"]

        domain_uses_https = row["Domain Supports HTTPS"] or domain_fallback_check
        domain_enforces_https = row["Domain Enforces HTTPS"] or domain_fallback_check
        domain_uses_strong_hsts = (
            row["Domain Uses Strong HSTS"] or domain_fallback_check
        )
        domain_uses_weak_crypto = row["Domain Supports Weak Crypto"]

        results[row["Domain"].lower()] = {}
        if not (
            domain_uses_https and domain_enforces_https and domain_uses_strong_hsts
        ):
            results[row["Domain"].lower()]["Live"] = row["Live"]
            results[row["Domain"].lower()]["Base Domain HSTS Preloaded"] = row[
                "Base Domain HSTS Preloaded"
            ]

            if not domain_uses_https:
                results[row["Domain"].lower()]["Domain Supports HTTPS"] = row[
                    "Domain Supports HTTPS"
                ]
            if not domain_enforces_https:
                results[row["Domain"].lower()]["Domain Enforces HTTPS"] = row[
                    "Domain Enforces HTTPS"
                ]
            if not domain_uses_strong_hsts:
                results[row["Domain"].lower()]["Domain Uses Strong HSTS"] = row[
                    "Domain Uses Strong HSTS"
                ]

        if domain_uses_weak_crypto:
            results[row["Domain"].lower()]["Domain Uses Weak Crypto"] = row[
                "Web Hosts With Weak Crypto"
            ]

    for k, v in results.items():
        if v:
            output_domain_results(k, v)
