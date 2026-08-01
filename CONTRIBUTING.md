# Contributing to TLSOTP

Thanks for your interest in contributing! TLSOTP is a small, dependency-free
library, so the bar for contributions is intentionally simple.

## Getting started

```bash
git clone https://github.com/ASH-SuperUser/tlsotp.git
cd tlsotp
python -m venv venv
venv\Scripts\activate        # on Windows
source venv/bin/activate     # on macOS / Linux
pip install -e .[dev]
```

## Development workflow

- Write or update tests in `tests/` for any behaviour change. Run the suite:

  ```bash
  pytest
  ```

- Keep the linter happy:

  ```bash
  ruff check src tests
  ```

- Keep the type checker happy (the package advertises `Typing :: Typed`):

  ```bash
  mypy
  ```

- Keep the docs buildable (API pages are generated from docstrings):

  ```bash
  mkdocs build
  ```

## Code style

- Follow the existing code style and naming conventions.
- Do **not** add runtime dependencies — the library is stdlib-only by design.
- Do not add comments unless they genuinely explain non-obvious logic.
- Public functions must have Google-style docstrings (they feed the docs site).

## Docs

Documentation lives in `docs/` (MkDocs + mkdocstrings). When you change a
public function or its docstring, rebuild the docs to confirm nothing breaks:

```bash
mkdocs serve
```

If you edit code references that point at specific lines (e.g. in
`docs/comparison-with-totp.md`), make sure the line numbers are accurate.

## Commits

- Write concise, descriptive commit messages.
- Reference any related issue in the commit body.

## Pull requests

1. Fork the repository and create a feature branch.
2. Make your change and add/update tests.
3. Run `pytest`, `ruff check src tests`, and `mypy` locally.
4. Open a PR against `main` and describe the change.

Found a bug or want a feature? Open an
[issue](https://github.com/ASH-SuperUser/tlsotp/issues) first.
