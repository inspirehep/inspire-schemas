from __future__ import (
    absolute_import,
    division,
    print_function,
)

import os


def get_test_suite_path(*path_chunks):
    """
    Args:
        *path_chunks: Optional extra path element (strings) to suffix the responses directory with.
        **kwargs: The test type folder name, default is the ``unit`` test suite,
            e.g. ``test_suite='unit'``, ``test_suite='functional'``.

    Returns:
        str: The absolute path to the test folder, if ``path_chuncks`` and ``kwargs``
            provided the absolute path to path chunks.

    Examples:
        Default::

            >>> get_test_suite_path()
            '/home/myuser/inspire_utils/tests'

        Using ``path_chunks`` and ``kwargs``::

            >>> get_test_suite_path('one', 'two', test_suite='functional')
            '/home/myuser/inspire_utils/tests/functional/one/two'
    """
    project_root_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
        )
    )
    return os.path.join(project_root_dir, "unit", "data", *path_chunks)
