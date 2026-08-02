How to Contribute
=================

Head over to: https://github.com/graingert/anyldap and submit your bugs or
feature requests.

If you wish to contribute code, just fork it,
make a branch and send us a pull request.
We'll review it, and push back if necessary.

Check docs/PULL_REQUEST_TEMPLATE.md for more info about how to pull request
process.

anyldap follows the repository's current coding and documentation standards.


Development environment
-----------------------

Tox is used to manage both local development and CI environment.

The recommended local dev enviroment is `tox -e py312-test-dev`

When running on local dev env, you will get a coverage report for whole
code as well as for the changes since `master`.
The reports are also produced in HTML at:

* build/coverage-html/index.html
* build/coverage-diff.html

You can run a subset of the test by passing the dotted path to the test or
test case, test module or test package::

    tox -e py312-test-dev anyldap.test.test_delta.TestModifyOp.testAsLDIF
    tox -e py312-test-dev anyldap.test.test_usage


Release notes
-------------

To simplify the release process each change should be recorded into the
docs/source/NEWS.rst in a wording targeted to end users.
Try not to write the release notes as a commit message.


Release process
---------------

The release is done automatically via GitHub actions when a new ``v*`` tag
is pushed. The version itself comes from that tag via setuptools-scm, so
there is no version to edit anywhere in the source:

1. pick a new version number!
2. update the latest version and release date in ``docs/source/NEWS.rst``,
   and commit that on ``main``.
3. tag the new release ``git tag v{version} -m 'Tagging {version}'``
4. push it with ``git push origin v{version}``

The tag has to be on a commit reachable from ``main``, otherwise
setuptools-scm cannot find it and will fall back to a placeholder version.

PyPI access is done via PyPI Trusted Publishing configured for the `pypi`
GitHub Actions environment and the repository at
https://github.com/graingert/anyldap/settings/environments

You can test the release process (without the publish) using `tox -e release`.
Inspect the distributable files with `tree dist`, you could upload them with `twine`.


Building the documentation
--------------------------

The documentation is managed using Python Sphinx and is generated in
build/docs.

There is a helper to build the documentation using tox ::

    tox -e documentation
