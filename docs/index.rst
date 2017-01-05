..
    This file is part of INSPIRE-SCHEMAS.
    Copyright (C) 2016 CERN.

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


.. include:: ../README.rst

User's Guide
------------

This part of the documentation will show you how to get started in using
inspire-schemas.

**NOTE**: it is highly encouraged to pin the version of ``inspire-schemas``
that you use to the major number, for example using the ``~=`` version matcher
in your ``requirements.txt`` or your ``setup.py`` like::

  inspire-schemas~=1.0.0

That will prevent any major update (compatibility breaking) to be pulled
automatically, and will only download minor and feature updates (1.X.Y).


.. toctree::
   :maxdepth: 2

   installation
   usage


API Reference
-------------

If you are looking for information on a specific function, class or method,
this part of the documentation is for you.

.. toctree::
   :maxdepth: 2

   api
   utils

Additional Notes
----------------

Notes on how to contribute, legal information and changes are here for the
interested.

.. toctree::
   :maxdepth: 1

   contributing
   license


Changelog
------------
Here you can find the `full changelog for this version`_


.. _full changelog for this version: _static/CHANGELOG.txt
