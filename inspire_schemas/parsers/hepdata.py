# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2024 CERN.
#
# INSPIRE-SCHEMAS is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# INSPIRE-SCHEMAS is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with INSPIRE-SCHEMAS; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307, USA.
#
# In applying this license, CERN does not
# waive the privileges and immunities granted to it by virtue of its status
# as an Intergovernmental Organization or submit itself to any jurisdiction.

"""Parser for HEPData format."""

from __future__ import absolute_import, division, print_function

import datetime
import re

import pytz
from inspire_utils.date import normalize_date

from inspire_schemas.builders import DataBuilder


class HEPDataParser(object):
    """Parser for HEPData format.

    It can be used directly by invoking the :func:`HEPDataParser.parse` method, or be
    subclassed to customize its behavior.

    Args:
        payload (dict): The HEPData payload containing base record and versions.
        inspire_url (str): Base URL for INSPIRE API references.
        source (Optional[str]): if provided, sets the ``source`` everywhere in
            the record. Otherwise, defaults to "HEPData".
    """

    def __init__(self, hepdata_record, inspire_url, source=None):
        self.payload = hepdata_record
        self.inspire_url = inspire_url
        self.source = source or "HEPData"
        self.builder = DataBuilder(source=self.source)

    def parse(self):
        """Extract a HEPData record into an Inspire Data record.

        Returns:
            dict: the record in the Inspire Data schema.
        """
        base_record = self.payload["base"]

        self._add_collaborations(base_record["record"])
        self._add_abstract(base_record["record"])
        self._add_keywords(base_record["record"])
        record_v1 = self.payload.get("1", base_record)
        self._add_date(record_v1["record"])
        self._add_literature_reference(base_record["record"])
        self._add_resources(base_record["record"])
        title = base_record["record"].get("title")
        if title:
            self.builder.add_title(title)
        self._add_acquisition_source(base_record["record"])
        self._add_dois(base_record["record"])

        for _, record_version in self.payload.items():
            data_tables = record_version.get("data_tables", [])
            for data_table in data_tables:
                table_doi = data_table.get("doi")
                if table_doi:
                    self.builder.add_doi(table_doi, material="part")
            resources_with_doi = record_version.get("resources_with_doi", [])
            for resource_with_doi in resources_with_doi:
                resource_doi = resource_with_doi.get("doi")
                if resource_doi:
                    self.builder.add_doi(resource_doi, material="part")
            self._add_version_specific_dois(record_version["record"])

        return self.builder.record

    def _add_keywords(self, record):
        """Add keywords from HEPData record."""
        for keyword, item in record.get("data_keywords", {}).items():
            if keyword == "cmenergies":
                if len(item) >= 1 and "lte" in item[0] and "gte" in item[0]:
                    self.builder.add_keyword(
                        "{}: {}-{}".format(keyword, item[0]["lte"], item[0]["gte"])
                    )
            elif keyword == "observables":
                for value in item:
                    self.builder.add_keyword("observables: {}".format(value))
            else:
                for value in item:
                    self.builder.add_keyword(value)

    def _add_date(self, record):
        """Add date to the record."""
        creation_date = record["creation_date"]
        last_updated = record.get("last_updated")
        final_date = creation_date
        if last_updated:
            try:
                last_updated = normalize_date(last_updated)
                if last_updated != "1970-01-01":  # Dummy date added by HEPData
                    final_date = last_updated
            except ValueError:
                pass
        self.builder.add_creation_date(final_date)

    def _add_literature_reference(self, record):
        """Add literature reference to the record."""
        doi = record.get("doi")
        inspire_id = record["inspire_id"]

        if doi:
            self.builder.add_literature(
                doi=doi,
                record={"$ref": "{}/api/literature/{}".format(self.inspire_url, inspire_id)},
            )
        else:
            self.builder.add_literature(
                record={"$ref": "{}/api/literature/{}".format(self.inspire_url, inspire_id)},
            )

    def _add_resources(self, record):
        """Add URLs from HEPData resources, filtering out internal HEPData URLs."""
        resources = record.get("resources", [])
        for resource in resources:
            url = resource.get("url")
            if url and not url.startswith("https://www.hepdata.net/record/resource/"):
                description = resource.get("description", "")
                self.builder.add_url(url, description)

    def _add_acquisition_source(self, record):
        """Add acquisition source information."""
        inspire_id = record.get("inspire_id")
        if inspire_id:
            self.builder.add_acquisition_source(
                method="inspirehep",
                submission_number=inspire_id,
                datetime=datetime.datetime.now(pytz.UTC).isoformat(),
            )

    def _add_collaborations(self, record):
        """Add collaboration information."""
        collaborations = record.get("collaborations", [])
        for collab in collaborations:
            self.builder.add_collaboration(collab)

    def _add_abstract(self, record):
        """Add data_abstract information."""
        data_abstract = record.get("data_abstract")
        self.builder.add_abstract(data_abstract)

    def _add_dois(self, record):
        """Add main DOI to the record."""
        hepdata_doi = record["hepdata_doi"]

        mtc = re.match(r"(.*?)\.v\d+", hepdata_doi)
        if mtc:
            self.builder.add_doi(doi=mtc.group(1), material="data")
        else:
            self.builder.add_doi(doi=hepdata_doi, material="data")

    def _add_version_specific_dois(self, record):
        """Add version-specific DOIs to the record."""
        data_tables = record.get("data_tables", [])
        for data_table in data_tables:
            table_doi = data_table.get("doi")
            if table_doi:
                self.builder.add_doi(table_doi, material="part")

        resources_with_doi = record.get("resources_with_doi", [])
        for resource_with_doi in resources_with_doi:
            resource_doi = resource_with_doi.get("doi")
            if resource_doi:
                self.builder.add_doi(resource_doi, material="part")

        base_record = record.get("record", {})
        version_doi = base_record.get("hepdata_doi")
        if version_doi:
            self.builder.add_doi(version_doi, material="version")

    def _add_version_specific_dois(self, record_version):
        """Add DOIs specific to a particular version of the HEPData record."""
        version_doi = record_version.get("hepdata_doi")
        if version_doi:
            self.builder.add_doi(version_doi, material="version")
