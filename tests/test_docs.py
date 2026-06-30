"""Run the public API's docstring examples as tests (cf. obsigil-rs doctests).

``importlib`` is used because ``obsigil.mint`` / ``obsigil.clauses`` resolve to
the re-exported *functions*, not their modules; ``import_module`` returns the
module object regardless.
"""

import doctest
import importlib


def test_docstring_examples_run():
    for name in ("mint", "verify", "manifest", "uuid7", "core"):
        mod = importlib.import_module(f"obsigil.{name}")
        result = doctest.testmod(mod)
        assert result.failed == 0, f"obsigil.{name}: {result.failed} doctest failure(s)"
        assert result.attempted > 0, f"obsigil.{name}: no doctests ran"
