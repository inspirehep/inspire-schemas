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

from inspire_schemas.parsers.author_xml import AuthorXMLParser


def test_parsing_author_xml():
    data = """
    <collaborationauthorlist xmlns:foaf="http://xmlns.com/foaf/0.1/" xmlns:cal="http://inspirehep.net/info/HepNames/tools/authors_xml/">
    <cal:creationDate>2022-01-25</cal:creationDate>
    <cal:publicationReference>Fermilab-PUB-2022-01-25</cal:publicationReference>
    <cal:collaborations>
    <cal:collaboration id="duneid">
    <foaf:name>DUNE</foaf:name>
    <cal:experimentNumber>DUNE</cal:experimentNumber>
    </cal:collaboration>
    </cal:collaborations>
    <cal:authors>
        <foaf:Person>
            <foaf:name>Michael Finger</foaf:name>
            <foaf:givenName>Michael</foaf:givenName>
            <foaf:familyName>Finger</foaf:familyName>
            <cal:authorNameNative lang=""/>
            <cal:authorSuffix>Jr.</cal:authorSuffix>
            <cal:authorStatus/>
            <cal:authorNamePaper>M. Finger Jr.</cal:authorNamePaper>
            <cal:authorAffiliations>
            <cal:authorAffiliation organizationid="o27" connection=""/>
            <cal:authorAffiliation organizationid="vo1" connection="AlsoAt"/>
            </cal:authorAffiliations>
            <cal:authorIDs>
            <cal:authorID source="INSPIRE">INSPIRE-00171357</cal:authorID>
            <cal:authorID source="CCID">391883</cal:authorID>
            <cal:authorID source="ORCID">0000-0003-3155-2484</cal:authorID>
            </cal:authorIDs>
        </foaf:Person>
    </cal:authors>
    </collaborationauthorlist>
    """
    result = AuthorXMLParser(data).parse()
    assert result[0]["full_name"] == "Finger, Michael, Jr."
