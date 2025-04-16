# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE.
# Copyright (C) 2014-2024 CERN.
#
# INSPIRE is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# INSPIRE is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with INSPIRE. If not, see <http://www.gnu.org/licenses/>.
#
# In applying this license, CERN does not waive the privileges and immunities
# granted to it by virtue of its status as an Intergovernmental Organization
# or submit itself to any jurisdiction.

from __future__ import (
    absolute_import,
    division,
    print_function,
)

import six

from inspire_schemas.parsers.arxiv import ArxivParser


def test_latex_to_unicode_handles_arxiv_escape_sequences():
    expected = six.ensure_text("Kähler")
    result = ArxivParser.latex_to_unicode('K\\"{a}hler')

    assert result == expected


def test_latex_to_unicode_handles_non_arXiv_escape_sequences():
    expected = "\u03bd\u03bd\u0305process"
    if six.PY2:
        expected = expected.decode("unicode_escape")

    result = ArxivParser.latex_to_unicode(six.ensure_text("\\nu\\bar\\nu process"))

    assert result == expected


def test_latex_to_unicode_preserves_math():
    expected = six.ensure_text('$H_{\\text{Schr\\"{o}dinger}}$')
    result = ArxivParser.latex_to_unicode(six.ensure_text('$H_{\\text{Schr\\"{o}dinger}}$'))

    assert result == expected


def test_latex_to_unicode_preserves_braces_containing_more_than_one_char():
    expected = six.ensure_text(
        "On the origin of the Type~{\\sc ii} spicules - dynamic 3D MHD simulations"
    )
    result = ArxivParser.latex_to_unicode(
        six.ensure_text("On the origin of the Type~{\\sc ii} spicules - dynamic 3D MHD simulations")
    )

    assert result == expected


def test_latex_to_unicode_preserves_comments():
    expected = six.ensure_text(
        "A 4% measurement of $H_0$ using the cumulative"
        "distribution of strong-lensing time delays in doubly-imaged quasars"
    )
    result = ArxivParser.latex_to_unicode(
        six.ensure_text(
            "A 4% measurement of $H_0$ using the cumulative"
            "distribution of strong-lensing time delays in doubly-imaged quasars"
        )
    )

    assert result == expected


def test_latex_to_unicode_handles_parens_after_sqrt():
    expected = "at \u221a(s) =192-202 GeV"
    result = ArxivParser.latex_to_unicode("at  \\sqrt(s) =192-202 GeV")

    assert result == expected


def test_latex_to_unicode_handles_sqrt_without_parens():
    expected = "\u221a(s)"
    result = ArxivParser.latex_to_unicode(r"\sqrt s")

    assert result == expected


def test_latex_to_unicode_preserves_spacing_after_macros():
    expected = six.ensure_text("and DØ Experiments")
    result = ArxivParser.latex_to_unicode("and D\\O Experiments")

    assert result == expected
