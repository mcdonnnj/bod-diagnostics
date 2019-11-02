# bod-diagnostics #

[![GitHub Build Status](https://github.com/mcdonnnj/bod-diagnostics/workflows/build/badge.svg)](https://github.com/mcdonnnj/bod-diagnostics/actions)
[![Coverage Status](https://coveralls.io/repos/github/mcdonnnj/bod-diagnostics/badge.svg?branch=develop)](https://coveralls.io/github/mcdonnnj/bod-diagnostics?branch=develop)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/mcdonnnj/bod-diagnostics.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/mcdonnnj/bod-diagnostics/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/mcdonnnj/bod-diagnostics.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/mcdonnnj/bod-diagnostics/context:python)
[![Known Vulnerabilities](https://snyk.io/test/github/mcdonnnj/bod-diagnostics/develop/badge.svg)](https://snyk.io/test/github/mcdonnnj/bod-diagnostics)

This project provides a command line tool to perform simple diagnostics on
BOD 18-01 results by parsing the CSV files provided in a stakeholder's report
PDF. These are calculated outputs from the [pshtt](https://github.com/cisagov/pshtt)
or [trustymail](https://github.com/cisagov/trustymail) tools that have been run
through their respective reporters ([pshtt_reporter](https://github.com/cisagov/pshtt_reporter)
and [trustymail_reporter](https://github.com/cisagov/trustymail_reporter)).
Upon processing these CSVs the tool will provide granular information by
emulating the scoring taking place in the reporters to show what specific values
are failing for test values that are derived from multiple value checks.

## Contributing ##

We welcome contributions!  Please see [here](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
