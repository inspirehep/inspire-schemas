Installation
============

Install from PyPI:

.. code-block:: console

    pip install inspire-schemas


Install with Docker
===================

Prerequisite: install Docker on your machine.

Build the image from the repository root:

.. code-block:: console

    docker build -t inspire-schemas .

Run the test suite inside the container:

.. code-block:: console

    docker run -it inspire-schemas
    pytest tests/
