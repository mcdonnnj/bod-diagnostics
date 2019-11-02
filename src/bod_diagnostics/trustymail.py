"""
Script to provide BOD failure info for trustymail reports.

This script is designed to take the trustymail_results.csv file for a given
organization's report and provide more granular information about why domains
are failing. Additional information is given for DMARC and RUA URL failures
because the checks are more involved than single value true/false checks.
"""

from collections import defaultdict
import csv

from . import utils

bod_rua_url = "mailto:reports@dmarc.cyber.dhs.gov"


def parse_csv(csv_file, domains=None):
    """Parse a provided CSV file to provide trustymail diagnostic information."""
    count_values = defaultdict(lambda: 0)

    failed_domains = {
        "invalid_dmarc": {
            "title": "Domains With Invalid DMARC Configurations ::",
            "domains": [],
        },
        "invalid_rua": {
            "title": f'Domains Missing RUA URL "{bod_rua_url}" ::',
            "domains": [],
        },
    }
    domains = [domain.lower() for domain in domains]

    csv_reader = csv.DictReader(csv_file)
    for row in csv_reader:
        # If we specified domains we check to see if this is one we want
        if domains:
            if row["Domain"].lower() not in domains:
                continue

        row = utils.convert_booleans(row)

        count_values["total_domains"] += 1

        valid_dmarc = row["Valid DMARC"] or row["Valid DMARC Record on Base Domain"]
        valid_dmarc_policy_reject = valid_dmarc and (row["DMARC Policy"] == "reject")
        valid_dmarc_subdomain_policy_reject = valid_dmarc and (
            not row["Domain Is Base Domain"]
            or (row["DMARC Subdomain Policy"] == "reject")
        )
        valid_dmarc_policy_pct = valid_dmarc and (
            row["DMARC Policy Percentage"] == "100"
        )
        valid_dmarc_policy_of_reject = (
            valid_dmarc_policy_reject
            and valid_dmarc_subdomain_policy_reject
            and valid_dmarc_policy_pct
        )

        if row["Domain Is Base Domain"]:
            spf_covered = row["Valid SPF"]
        else:
            spf_covered = row["Valid SPF"] or (
                (not row["SPF Record"]) and valid_dmarc_policy_of_reject
            )

        valid_dmarc_bod1801_rua_url = False
        if valid_dmarc:
            if bod_rua_url in [
                u.strip().lower() for u in row["DMARC Aggregate Report URIs"].split(",")
            ]:
                valid_dmarc_bod1801_rua_url = True

        if row["Domain Is Base Domain"] or (
            not row["Domain Is Base Domain"] and row["Domain Supports SMTP"]
        ):
            count_values["domains_checked"] += 1
            if (row["Domain Supports SMTP"] and row["Domain Supports STARTTLS"]) or (
                not row["Domain Supports SMTP"]
            ):
                count_values["smtp_valid"] += 1
                if spf_covered:
                    count_values["spf_covered"] += 1
                    if not row["Domain Supports Weak Crypto"]:
                        count_values["no_weak_crypto"] += 1
                        if valid_dmarc_policy_of_reject:
                            count_values["dmarc_valid"] += 1
                            if valid_dmarc_bod1801_rua_url:
                                count_values["bod_compliant"] += 1
                            else:
                                count_values["bod_failed"] += 1
                                message = ["\tRUA URLs:"]
                                for url in [
                                    u.strip().lower()
                                    for u in row["DMARC Aggregate Report URIs"].split(
                                        ","
                                    )
                                ]:
                                    message.append(f"\t\t{url}")
                                failed_domains["invalid_rua"]["domains"].append(
                                    {"domain": row["Domain"], "message": message}
                                )
                        else:
                            count_values["dmarc_invalid"] += 1
                            message = [
                                f"\tBase Domain: {row['Domain Is Base Domain']}",
                                f"\tValid DMARC: {valid_dmarc}",
                                f"\tDMARC Policy: \"{row['DMARC Policy']}\"",
                                f"\tDMARC Subdomain Policy: \"{row['DMARC Subdomain Policy']}\"",
                                f"\tDMARC Policy Percentage: {row['DMARC Policy Percentage']}",
                                f"\tConditions (Must be True):",
                                f'\t\tValid DMARC and Policy == "reject": {valid_dmarc_policy_reject}',
                                f'\t\tValid DMARC and (not Base Domain or Subdomain Policy == "reject"): {valid_dmarc_subdomain_policy_reject}',
                                f"\t\tValid DMARC and Policy Percentage == 100: {valid_dmarc_policy_pct}",
                            ]
                            failed_domains["invalid_dmarc"]["domains"].append(
                                {"domain": row["Domain"], "message": message}
                            )
                    else:
                        count_values["has_weak_crypto"] += 1
                else:
                    count_values["spf_not_covered"] += 1
            else:
                count_values["smtp_invalid"] += 1
        else:
            count_values["domains_skipped"] += 1

    for k, v in failed_domains.items():
        if len(v["domains"]) == 0:
            continue
        print(v["title"])
        for domain in v["domains"]:
            print(f"\t{domain['domain']}")
            for line in domain["message"]:
                print(f"\t{line}")
        print()

    for k, v in count_values.items():
        print(f"{k} :: {v}")
