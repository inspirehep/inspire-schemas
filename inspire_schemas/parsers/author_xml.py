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

import re

from inspire_utils.name import normalize_name
from scrapy.selector import Selector
from six import binary_type
from six.moves import zip

from inspire_schemas.api import LiteratureBuilder


class AuthorXMLParser(object):
    def __init__(self, xml_content):
        self.xml_content = xml_content

        if isinstance(self.xml_content, binary_type):
            self.xml_content = self.xml_content.decode("utf-8")

        # Probably the %auto-ignore comment exists, so we skip the
        # first line. See: inspirehep/inspire-next/issues/2195
        if "%auto-ignore" in self.xml_content:
            self.xml_content = self.xml_content.split("\n", 1)[1]

    def parse(self):
        builder = LiteratureBuilder()
        content = Selector(text=self.xml_content, type="xml")
        content.remove_namespaces()
        undefined_or_none_value_regex = re.compile("undefined|none", re.IGNORECASE)
        undefined_or_empty_inspireid_value_regex = re.compile(
            "undefined|inspire-\s*$", re.IGNORECASE  # noqa
        )
        undefined_value_regex = re.compile("undefined", re.IGNORECASE)
        ror_path_value_regex = re.compile("https://ror.org/*")
        remove_new_line_regex = re.compile("\s*\n\s*")  # noqa

        # Goes through all the authors in the file
        for author in content.xpath("//Person"):

            ids = []
            affiliations = []
            affiliations_identifiers = []

            # Gets all the author ids
            for source, id in zip(
                author.xpath(
                    './authorIDs/authorID[@source!="" and text()!=""]/@source'
                    '| ./authorids/authorid[@source!="" and text()!=""]/@source'
                ).getall(),
                author.xpath(
                    './authorIDs/authorID[@source!="" and text()!=""]/text()'
                    '| ./authorids/authorid[@source!="" and text()!=""]/text()'
                ).getall(),
            ):
                source = re.sub(remove_new_line_regex, "", source)
                id = re.sub(remove_new_line_regex, "", id)
                if not re.match(undefined_value_regex, source) and not re.match(
                    undefined_or_empty_inspireid_value_regex, id
                ):
                    if source == "CCID":
                        ids.append(["CERN", id])
                    elif source == "INSPIRE":
                        ids.append(["{} ID".format(source), id])
                    else:
                        ids.append([source, id])

            # Gets all the names for affiliated organizations using the organization ids from author
            for affiliation in author.xpath(
                "./authorAffiliations/authorAffiliation/@organizationid"
            ).getall():
                orgName = content.xpath(
                    'string(//organizations/Organization[@id="{}"]/orgName[@source="spiresICN"'
                    'or @source="INSPIRE" and text()!="" ]/text())'.format(
                        affiliation
                    )
                ).get()

                cleaned_org_name = re.sub(remove_new_line_regex, "", orgName)
                if orgName and not re.match(
                    undefined_or_none_value_regex, cleaned_org_name
                ):
                    affiliations.append(cleaned_org_name)

                # Gets all the affiliations_identifiers for affiliated organizations
                # using the organization ids from author
                for value, source in zip(
                    content.xpath(
                        '//organizations/Organization[@id="{}"]/orgName[@source="ROR"'
                        'or @source="GRID" and text()!=""]/text()'.format(
                            affiliation
                        )
                    ).getall(),
                    content.xpath(
                        '//organizations/Organization[@id="{}"]/orgName[@source="ROR"'
                        'or @source="GRID" and text()!=""]/@source'.format(
                            affiliation
                        )
                    ).getall(),
                ):
                    source = re.sub(remove_new_line_regex, "", source)
                    value = re.sub(remove_new_line_regex, "", value)
                    if re.match(undefined_or_none_value_regex, source) or re.match(
                        undefined_or_none_value_regex, value
                    ):
                        continue

                    if source == "ROR" and not re.match(ror_path_value_regex, value):
                        value = "https://ror.org/{}".format(value)

                    affiliations_identifiers.append([source, value])

            name = "{}, {}".format(
                author.xpath(".//familyName/text()").get(),
                author.xpath(".//givenName/text()").get(),
            )
            name_suffix = author.xpath(".//authorSuffix/text()").get()
            if name_suffix:
                name += ", {}".format(name_suffix)
            name = normalize_name(name)

            # builds the info to a correct format with litratureBuilder()
            builder.add_author(
                builder.make_author(
                    full_name=name,
                    affiliations=affiliations,
                    ids=ids,
                    affiliations_identifiers=affiliations_identifiers,
                )
            )

        return builder.record.get("authors", [])
