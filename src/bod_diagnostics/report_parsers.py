"""Module to provide parsers for BOD 18-01 reports.

This module hosts a colletion of classes to parse a given report for more
detailed information about why a domain is failing BOD 18-01 checks.
"""
# Standard Python Libraries
from collections import defaultdict
import csv
import logging
import sys

from . import _utils


class HTTPSReport:
    """Class to analyze a pshtt produced HTTPS report for errors.

    This module is designed to take the pshtt-results.csv file for a given
    organization's report and provide more granular information about why domains
    are failing.
    """

    plain_values = [
        "Live",
        "Base Domain HSTS Preloaded",
        "Domain Supports HTTPS",
        "Domain Enforces HTTPS",
        "Domain Uses Strong HSTS",
    ]

    scoring = {
        "Uses HTTPS": "'Domain Supports HTTPS' or ('Live' and 'Base Domain HSTS Preloaded')",
        "Enforces HTTPS": "'Domain Enforces HTTPS' or ('Live' and 'Base Domain HSTS Preloaded')",
        "Uses Strong HSTS": "'Domain Uses Strong HSTS' or ('Live' and 'Base Domain HSTS Preloaded')",
        "BOD 18-01 Web Compliance": "('Domain Supports HTTPS' and 'Domain Enforces HTTPS' and 'Domain Uses Strong HSTS') "
        "or ('Live' and 'Base Domain HSTS Preloaded'))",
    }

    def __init__(self, domains=None, csv_output=False):
        """Set up internal variables."""
        self._domains = domains if domains else []
        self._domains = [domain.lower() for domain in self._domains]
        logging.debug(f"Domains provided: {self._domains}")
        self.csv_output = csv_output
        self._results = {}

    def _output_record(self, domain, values, csv_writer=None):
        if csv_writer:
            row = {"Domain": domain}
            for value in self.plain_values:
                row[value] = values[value]
            i = 0
            for score, desc in self.scoring.items():
                row[f"{score} - {desc}"] = values["Scores"][i]
                i += 1
            csv_writer.writerow(row)
        else:
            print(f"  {domain}")
            print("    pshtt Values:")
            for value in self.plain_values:
                print(f"      {value}: {values[value]}")
            print("    Scores:")
            i = 0
            for score, desc in self.scoring.items():
                print(f"      {score} : {desc}")
                print(f"      = {values['Scores'][i]}")
                i += 1

    def output_results(self):
        """Print the results of analysis."""
        csv_writer = None
        if self.csv_output:
            csv_fieldnames = ["Domain"]
            csv_fieldnames.extend(self.plain_values)
            for name, desc in self.scoring.items():
                csv_fieldnames.append(f"{name} - {desc}")
            csv_writer = csv.DictWriter(sys.stdout, csv_fieldnames)
            csv_writer.writeheader()
        else:
            print("Domains with Failing Checks ::")

        for k, v in self._results.items():
            if False not in v["Scores"]:
                continue
            else:
                self._output_record(k, v, csv_writer)

    def parse_row(self, csv_row):
        """Parse a provided CSV file to provide pshtt diagnostic information."""
        result_dict = {}

        # If we specified domains we check to see if this is one we want
        if self._domains:
            if csv_row["Domain"].lower() not in self._domains:
                return

        csv_row = _utils.convert_booleans(csv_row)
        domain_live = csv_row["Live"]
        domain_hsts_preload = csv_row["Base Domain HSTS Preloaded"]
        domain_fallback_check = domain_live and domain_hsts_preload
        domain_supports_https = csv_row["Domain Supports HTTPS"]
        domain_enforces_https = csv_row["Domain Enforces HTTPS"]
        domain_strong_hsts = csv_row["Domain Uses Strong HSTS"]

        result_dict["Live"] = domain_live
        result_dict["Base Domain HSTS Preloaded"] = domain_hsts_preload
        result_dict["Domain Supports HTTPS"] = domain_supports_https
        result_dict["Domain Enforces HTTPS"] = domain_enforces_https
        result_dict["Domain Uses Strong HSTS"] = domain_strong_hsts
        result_dict["Scores"] = [
            (domain_supports_https or domain_fallback_check),
            (domain_enforces_https or domain_fallback_check),
            (domain_strong_hsts or domain_fallback_check),
            (
                (domain_supports_https and domain_enforces_https and domain_strong_hsts)
                or domain_fallback_check
            ),
        ]
        self._results[csv_row["Domain"].lower()] = result_dict


class TrustymailReport:
    """Class to analyze a trustymail produced HTTPS report for errors.

    This class is designed to take the trustymail_results.csv file for a given
    organization's report and provide more granular information about why domains
    are failing. Additional information is given for DMARC and RUA URL failures
    because the checks are more involved than single value true/false checks.
    """

    bod_rua_url = "mailto:reports@dmarc.cyber.dhs.gov"

    plain_values = [
        "Base Domain",
        "Valid DMARC",
        "DMARC Policy",
        "DMARC Subdomain Policy",
        "DMARC Policy Percentage",
    ]

    conditions = [
        "'Valid DMARC' == \"reject\"",
        "'Valid DMARc' and (not 'Base Domain' or 'DMARC Subdomain Policy' == \"reject\")",
        "'Valid DMARC' and 'Policy Percentage' == 100",
    ]

    def __init__(self, domains=None, csv_output=False):
        """Set up internal variables."""
        self._domains = domains if domains else []
        self._domains = [domain.lower() for domain in self._domains]
        logging.debug(f"Domains provided: {self._domains}")

        self.csv_output = csv_output
        self._count_values = defaultdict(lambda: 0)
        self._failed_domains = []

    def output_results(self):
        """Print the results of analysis."""
        if self.csv_output:
            csv_fieldnames = ["Domain"]
            csv_fieldnames.extend(self.plain_values)
            csv_fieldnames.extend(self.conditions)
            csv_fieldnames.append(f"RUA URLs (should contain '{self.bod_rua_url}')")
            csv_writer = csv.DictWriter(sys.stdout, csv_fieldnames)
            csv_writer.writeheader()

            for record in self._failed_domains:
                row = {"Domain": record["domain"]}
                for value in self.plain_values:
                    row[value] = record["result"][value]
                i = 0
                for condition in self.conditions:
                    row[condition] = record["result"]["Conditions"][i]
                    i += 1
                row[f"RUA URLs (should contain '{self.bod_rua_url}')"] = ";".join(
                    record["result"]["RUA URLs"]
                )
                csv_writer.writerow(row)
        else:
            for record in self._failed_domains:
                print(f"  {record['domain']}")
                for value in self.plain_values:
                    print(f"    {value} : {record['result'][value]}")
                print("    Conditions (must be true):")
                for d, c in zip(self.conditions, record["result"]["Conditions"]):
                    print(f"      {d} : {c}")
                if len(record["result"]["RUA URLs"]) > 0:
                    print(f"    RUA URLs (should contain '{self.bod_rua_url}'):")
                    for url in record["result"]["RUA URLs"]:
                        print(f"      {url}")
            print()

            for k, v in self._count_values.items():
                print(f"{k} :: {v}")

    def parse_row(self, csv_row):
        """Parse a provided CSV file to provide trustymail diagnostic information."""
        # If we specified domains we check to see if this is one we want
        if self._domains:
            if csv_row["Domain"].lower() not in self._domains:
                return

        csv_row = _utils.convert_booleans(csv_row)

        self._count_values["total_domains"] += 1

        valid_dmarc = (
            csv_row["Valid DMARC"] or csv_row["Valid DMARC Record on Base Domain"]
        )
        valid_dmarc_policy_reject = valid_dmarc and (
            csv_row["DMARC Policy"] == "reject"
        )
        valid_dmarc_subdomain_policy_reject = valid_dmarc and (
            not csv_row["Domain Is Base Domain"]
            or (csv_row["DMARC Subdomain Policy"] == "reject")
        )
        valid_dmarc_policy_pct = valid_dmarc and (
            csv_row["DMARC Policy Percentage"] == "100"
        )
        valid_dmarc_policy_of_reject = (
            valid_dmarc_policy_reject
            and valid_dmarc_subdomain_policy_reject
            and valid_dmarc_policy_pct
        )

        if csv_row["Domain Is Base Domain"]:
            spf_covered = csv_row["Valid SPF"]
        else:
            spf_covered = csv_row["Valid SPF"] or (
                (not csv_row["SPF Record"]) and valid_dmarc_policy_of_reject
            )

        valid_dmarc_bod1801_rua_url = False
        if valid_dmarc:
            if self.bod_rua_url in [
                u.strip().lower()
                for u in csv_row["DMARC Aggregate Report URIs"].split(",")
            ]:
                valid_dmarc_bod1801_rua_url = True

        if csv_row["Domain Is Base Domain"] or (
            not csv_row["Domain Is Base Domain"] and csv_row["Domain Supports SMTP"]
        ):
            self._count_values["domains_checked"] += 1
            if (
                csv_row["Domain Supports SMTP"] and csv_row["Domain Supports STARTTLS"]
            ) or (not csv_row["Domain Supports SMTP"]):
                self._count_values["smtp_valid"] += 1
                if spf_covered:
                    self._count_values["spf_covered"] += 1
                    if not csv_row["Domain Supports Weak Crypto"]:
                        self._count_values["no_weak_crypto"] += 1
                        if valid_dmarc_policy_of_reject:
                            self._count_values["dmarc_valid"] += 1
                            if valid_dmarc_bod1801_rua_url:
                                self._count_values["bod_compliant"] += 1
                            else:
                                self._count_values["bod_failed"] += 1
                        else:
                            self._count_values["dmarc_invalid"] += 1
                            result = {
                                "Base Domain": csv_row["Domain Is Base Domain"],
                                "Valid DMARC": valid_dmarc,
                                "DMARC Policy": csv_row["DMARC Policy"],
                                "DMARC Subdomain Policy": csv_row[
                                    "DMARC Subdomain Policy"
                                ],
                                "DMARC Policy Percentage": csv_row[
                                    "DMARC Policy Percentage"
                                ],
                                "Conditions": [
                                    valid_dmarc_policy_reject,
                                    valid_dmarc_subdomain_policy_reject,
                                    valid_dmarc_policy_pct,
                                ],
                                "RUA URLs": [
                                    u.strip().lower()
                                    for u in csv_row[
                                        "DMARC Aggregate Report URIs"
                                    ].split(",")
                                ],
                            }
                            self._failed_domains.append(
                                {"domain": csv_row["Domain"], "result": result}
                            )
                    else:
                        self._count_values["has_weak_crypto"] += 1
                else:
                    self._count_values["spf_not_covered"] += 1
            else:
                self._count_values["smtp_invalid"] += 1
        else:
            self._count_values["domains_skipped"] += 1
