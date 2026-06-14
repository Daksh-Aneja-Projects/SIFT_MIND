from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


class PackagingMetadataTests(unittest.TestCase):
    def test_all_extra_is_explicit_union_without_self_reference(self) -> None:
        pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
        metadata = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        extras = metadata["project"]["optional-dependencies"]

        all_extra = set(extras["all"])
        expected = set()
        for name, dependencies in extras.items():
            if name != "all":
                expected.update(dependencies)

        self.assertEqual(expected, all_extra)
        self.assertFalse(
            any(item.lower().startswith("sift-mind") for item in all_extra),
            "The all extra must not depend on the package itself.",
        )

    def test_requirements_are_covered_by_pyproject_all_install(self) -> None:
        root = Path(__file__).resolve().parents[1]
        metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        pyproject_specs = set(metadata["project"]["dependencies"])
        pyproject_specs.update(metadata["project"]["optional-dependencies"]["all"])
        requirements_specs = {
            line.split("#", 1)[0].strip()
            for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.split("#", 1)[0].strip()
        }

        self.assertEqual(requirements_specs, pyproject_specs)


if __name__ == "__main__":
    unittest.main()
