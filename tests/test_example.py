#!/usr/bin/env pytest -vs
"""Tests for bod-diagnostics."""

import logging
import os
import sys
from unittest.mock import patch

import pytest

import bod_diagnostics

log_levels = (
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    pytest.param("critical2", marks=pytest.mark.xfail),
)

# define sources of version strings
RELEASE_TAG = os.getenv("RELEASE_TAG")
PROJECT_VERSION = bod_diagnostics.__version__


def test_stdout_version(capsys):
    """Verify that version string sent to stdout agrees with the module version."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            bod_diagnostics.cli.main()
    captured = capsys.readouterr()
    assert (
        captured.out == f"{PROJECT_VERSION}\n"
    ), "standard output by '--version' should agree with module.__version__"


@pytest.mark.skipif(
    RELEASE_TAG in [None, ""], reason="this is not a release (RELEASE_TAG not set)"
)
def test_release_version():
    """Verify that release tag version agrees with the module version."""
    assert (
        RELEASE_TAG == f"v{PROJECT_VERSION}"
    ), "RELEASE_TAG does not match the project version"


@pytest.mark.parametrize("level", log_levels)
def test_log_levels(level):
    """Validate commandline log-level arguments."""
    with patch.object(sys, "argv", ["bogus", f"--log-level={level}"]):
        with patch.object(logging.root, "handlers", []):
            assert (
                logging.root.hasHandlers() is False
            ), "root logger should not have handlers yet"
            return_code = bod_diagnostics.cli.main()
            assert (
                logging.root.hasHandlers() is True
            ), "root logger should now have a handler"
            assert return_code == 0, "main() should return success (0)"
