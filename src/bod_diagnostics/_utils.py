"""Provide utility functions for the bod-diagnostics tool."""


def convert_booleans(row):
    """Convert string true/false values into Python booleans in a given row."""
    for k, v in row.items():
        if v is None:
            continue
        if v.strip().lower() == "true":
            row[k] = True
        elif v.strip().lower() == "false":
            row[k] = False

    return row
