"""A Pure-Python AnyIO library for LDAP."""
from importlib.metadata import PackageNotFoundError, version

from exceptiongroup import suppress

# setuptools-scm builds the version from the git tag, so there is nothing to
# read from an uninstalled source tree.
with suppress(PackageNotFoundError):
    __version__ = version("anyldap")

__title__ = "anyldap"
__description__ = "A Pure-Python AnyIO library for LDAP"
__uri__ = "https://github.com/graingert/anyldap"

__license__ = "MIT"
__author__ = "The anyldap developers"
__copyright__ = f"Copyright (c) 2002-2021 {__author__}"
