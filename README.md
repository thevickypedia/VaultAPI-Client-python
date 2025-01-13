# VaultAPI-Client-python-
Client application for VaultAPI Server

![Python][label-pyversion]

**Platform Supported**

![Platform][label-platform]

**Deployments**

[![pypi][label-actions-pypi]][gha_pypi]
[![markdown][label-actions-markdown]][gha_md_valid]

[![Pypi][label-pypi]][pypi]
[![Pypi-format][label-pypi-format]][pypi-files]
[![Pypi-status][label-pypi-status]][pypi]

## Kick off

**Recommendations**

- Install `python` [3.10] or [3.11]
- Use a dedicated [virtual environment]

**Install VaultAPI**
```shell
python -m pip install vaultapi
```

**Initiate - IDE**
```python
import vaultapi


if __name__ == '__main__':
    vaultapi.decrypt(get_secret="mykey", table="mytable")
```

**Initiate - CLI**
```shell
vaultapi --table mytable
```

> Use `vaultapi --help` for usage instructions.

## Environment Variables

<details>
<summary><strong>Sourcing environment variables from an env file</strong></summary>

> _By default, `VaultAPI` will look for a `.env` file in the current working directory._
</details>

**Mandatory**
- **APIKEY** - API Key for authentication.
- **VAULT_SERVER** - VaultAPI server URL.

## Coding Standards
Docstring format: [`Google`][google-docs] <br>
Styling conventions: [`PEP 8`][pep8] and [`isort`][isort]

## Linting
`pre-commit` will ensure linting, run pytest, generate runbook & release notes, and validate hyperlinks in ALL
markdown files (including Wiki pages)

**Requirement**
```shell
python -m pip install pre-commit
```

**Usage**
```shell
pre-commit run --all-files
```

## Pypi Package
[![pypi-module][label-pypi-package]][pypi-repo]

[https://pypi.org/project/VaultAPI-Client-python/][pypi]

## License & copyright

&copy; Vignesh Rao

Licensed under the [MIT License][license]

[label-actions-markdown]: https://github.com/thevickypedia/VaultAPI-Client-python/actions/workflows/markdown.yml/badge.svg
[label-pypi-package]: https://img.shields.io/badge/Pypi%20Package-VaultAPI-blue?style=for-the-badge&logo=Python
[label-pyversion]: https://img.shields.io/badge/python-3.10%20%7C%203.11-blue
[label-platform]: https://img.shields.io/badge/Platform-Linux|macOS|Windows-1f425f.svg
[label-actions-pypi]: https://github.com/thevickypedia/VaultAPI-Client-python/actions/workflows/python-publish.yml/badge.svg
[label-pypi]: https://img.shields.io/pypi/v/VaultAPI-Client-python
[label-pypi-format]: https://img.shields.io/pypi/format/VaultAPI-Client-python
[label-pypi-status]: https://img.shields.io/pypi/status/VaultAPI-Client-python

[3.10]: https://docs.python.org/3/whatsnew/3.10.html
[3.11]: https://docs.python.org/3/whatsnew/3.11.html
[virtual environment]: https://docs.python.org/3/tutorial/venv.html
[release-notes]: https://github.com/thevickypedia/VaultAPI-Client-python/blob/main/release_notes.rst
[gha_pages]: https://github.com/thevickypedia/VaultAPI-Client-python/actions/workflows/pages/pages-build-deployment
[gha_pypi]: https://github.com/thevickypedia/VaultAPI-Client-python/actions/workflows/python-publish.yml
[gha_md_valid]: https://github.com/thevickypedia/VaultAPI-Client-python/actions/workflows/markdown.yml
[google-docs]: https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings
[pep8]: https://www.python.org/dev/peps/pep-0008/
[isort]: https://pycqa.github.io/isort/
[pypi]: https://pypi.org/project/VaultAPI
[pypi-files]: https://pypi.org/project/VaultAPI-Client-python/#files
[pypi-repo]: https://packaging.python.org/tutorials/packaging-projects/
[license]: https://github.com/thevickypedia/VaultAPI-Client-python/blob/main/LICENSE
