"""
Module to provide BOD failure info for trustymail reports.

This module is designed to take the trustymail_results.csv file for a given
organization's report and provide more granular information about why domains
are failing. Additional information is given for DMARC and RUA URL failures
because the checks are more involved than single value true/false checks.
"""

from collections import defaultdict
import logging

from . import _utils


class TrustymailReport:
    """Class to analyze a trustymail produced HTTPS report for errors."""

    def __init__(self, domains=None):
        """Set up internal variables."""
        self.__domains = domains if domains else []
        self.__domains = [domain.lower() for domain in self.__domains]
        logging.debug(f"Domains provided: {self.__domains}")

        self.__count_values = defaultdict(lambda: 0)
        self.__failed_domains = {
            "invalid_dmarc": {
                "title": "Domains With Invalid DMARC Configurations ::",
                "domains": [],
            },
            "invalid_rua": {
                "title": f'Domains Missing RUA URL "{self.__bod_rua_url}" ::',
                "domains": [],
            },
        }
        self.__bod_rua_url = "mailto:reports@dmarc.cyber.dhs.gov"

    def output_results(self):
        """Print the results of analysis."""
        for k, v in self.__failed_domains.items():
            if len(v["domains"]) == 0:
                continue
            print(v["title"])
            for domain in v["domains"]:
                print(f"\t{domain['domain']}")
                for line in domain["message"]:
                    print(f"\t{line}")
            print()

        for k, v in self.__count_values.items():
            print(f"{k} :: {v}")

    def parse_row(self, csv_row):
        """Parse a provided CSV file to provide trustymail diagnostic information."""
        # If we specified domains we check to see if this is one we want
        if self.__domains:
            if csv_row["Domain"].lower() not in self.__domains:
                return

        csv_row = _utils.convert_booleans(csv_row)

        self.__count_values["total_domains"] += 1

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
            if self.__bod_rua_url in [
                u.strip().lower()
                for u in csv_row["DMARC Aggregate Report URIs"].split(",")
            ]:
                valid_dmarc_bod1801_rua_url = True

        if csv_row["Domain Is Base Domain"] or (
            not csv_row["Domain Is Base Domain"] and csv_row["Domain Supports SMTP"]
        ):
            self.__count_values["domains_checked"] += 1
            if (
                csv_row["Domain Supports SMTP"] and csv_row["Domain Supports STARTTLS"]
            ) or (not csv_row["Domain Supports SMTP"]):
                self.__count_values["smtp_valid"] += 1
                if spf_covered:
                    self.__count_values["spf_covered"] += 1
                    if not csv_row["Domain Supports Weak Crypto"]:
                        self.__count_values["no_weak_crypto"] += 1
                        if valid_dmarc_policy_of_reject:
                            self.__count_values["dmarc_valid"] += 1
                            if valid_dmarc_bod1801_rua_url:
                                self.__count_values["bod_compliant"] += 1
                            else:
                                self.__count_values["bod_failed"] += 1
                                message = ["\tRUA URLs:"]
                                for url in [
                                    u.strip().lower()
                                    for u in csv_row[
                                        "DMARC Aggregate Report URIs"
                                    ].split(",")
                                ]:
                                    message.append(f"\t\t{url}")
                                self.__failed_domains["invalid_rua"]["domains"].append(
                                    {"domain": csv_row["Domain"], "message": message}
                                )
                        else:
                            self.__count_values["dmarc_invalid"] += 1
                            message = [
                                f"\tBase Domain: {csv_row['Domain Is Base Domain']}",
                                f"\tValid DMARC: {valid_dmarc}",
                                f"\tDMARC Policy: \"{csv_row['DMARC Policy']}\"",
                                f"\tDMARC Subdomain Policy: \"{csv_row['DMARC Subdomain Policy']}\"",
                                f"\tDMARC Policy Percentage: {csv_row['DMARC Policy Percentage']}",
                                f"\tConditions (Must be True):",
                                f'\t\tValid DMARC and Policy == "reject": {valid_dmarc_policy_reject}',
                                f'\t\tValid DMARC and (not Base Domain or Subdomain Policy == "reject"): {valid_dmarc_subdomain_policy_reject}',
                                f"\t\tValid DMARC and Policy Percentage == 100: {valid_dmarc_policy_pct}",
                            ]
                            self.__failed_domains["invalid_dmarc"]["domains"].append(
                                {"domain": csv_row["Domain"], "message": message}
                            )
                    else:
                        self.__count_values["has_weak_crypto"] += 1
                else:
                    self.__count_values["spf_not_covered"] += 1
            else:
                self.__count_values["smtp_invalid"] += 1
        else:
            self.__count_values["domains_skipped"] += 1
