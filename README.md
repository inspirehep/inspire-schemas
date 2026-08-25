<!--
This file is part of INSPIRE-SCHEMAS.
Copyright (C) 2023 CERN.

INSPIRE-SCHEMAS is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

INSPIRE-SCHEMAS is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with INSPIRE-SCHEMAS; if not, write to the
Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
MA 02111-1307, USA.

In applying this license, CERN does not
waive the privileges and immunities granted to it by virtue of its status
as an Intergovernmental Organization or submit itself to any jurisdiction.
-->

# inspire-schemas

[![Tests](https://github.com/inspirehep/inspire-schemas/actions/workflows/push-master.yml/badge.svg)](https://github.com/inspirehep/inspire-schemas/actions/workflows/push-master.yml)
[![Coverage](https://img.shields.io/coveralls/inspirehep/inspire-schemas.svg)](https://coveralls.io/r/inspirehep/inspire-schemas)
[![Release](https://img.shields.io/github/tag/inspirehep/inspire-schemas.svg)](https://github.com/inspirehep/inspire-schemas/releases)
[![PyPI downloads](https://img.shields.io/pypi/dm/inspire-schemas.svg)](https://pypi.org/project/inspire-schemas/)
[![License](https://img.shields.io/github/license/inspirehep/inspire-schemas.svg)](LICENSE)

INSPIRE JSON schemas and related tools.

- [Documentation](https://inspire-schemas.readthedocs.io)
- [License](LICENSE)

## Installation

Requires Python 3.11 or newer. Install from PyPI:

```sh
pip install inspire-schemas
```

### Docker

Install Docker, then build the image from the repository root:

```sh
docker build -t inspire-schemas .
```

Start a shell inside the container:

```sh
docker run -it inspire-schemas
```

Run the tests from that shell:

```sh
pytest tests/
```

## Contributing

Bug fixes, features, and documentation improvements are welcome. Use the
[issue tracker](https://github.com/inspirehep/inspire-schemas/issues) to report
bugs or suggest features. For bugs, include your operating system, relevant
setup details, and steps to reproduce. For features, explain the proposed
behavior and keep the scope focused.

### Development setup

Fork [inspire-schemas](https://github.com/inspirehep/inspire-schemas), then
clone your fork. Install Python 3.11 or newer and Poetry, and run:

```sh
git clone git@github.com:your_name_here/inspire-schemas.git
cd inspire-schemas
poetry install --with test,docs
git checkout -b name-of-your-bugfix-or-feature
```

Run the test suite:

```sh
poetry run pytest
```

The test run reports coverage, including missing lines. Code style is checked
separately by pre-commit in CI.

### Pull requests

- Include tests and avoid decreasing test coverage.
- Update documentation and add docstrings for new functionality.
- Ensure GitHub Actions passes on all supported Python versions, starting
  with Python 3.11.

Commit with a sign-off and a descriptive message, push your branch, and open
a pull request on GitHub:

```sh
git add .
git commit -s -m "component: describe your change"
git push origin name-of-your-bugfix-or-feature
```

When applicable, include `Sem-Ver: new feature` or `Sem-Ver: breaks api` in
the commit message body.
