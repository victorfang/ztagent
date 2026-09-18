# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

from pathlib import Path

ATTRIBUTION = (
    "Victor Fang",
    "https://VictorFang.com",
    "https://X.com/vicfcs",
    "https://www.linkedin.com/in/drvictorfang",
)
HEADER = "# ZTAgent.ai : Zero Trust Security for AI Agents\n# Author: VictorFang.com\n"


def test_source_files_carry_compact_brand_header() -> None:
    files = [
        *Path("src").rglob("*.py"),
        *Path("tests").rglob("*.py"),
        *Path("config").rglob("*.yaml"),
        Path("src/ztagent_core/py.typed"),
        Path("app.py"),
        Path("compose.yaml"),
        Path("policies/authz.rego"),
        Path(".env.example"),
    ]
    for path in files:
        content = path.read_text(encoding="utf-8")
        assert content.startswith(HEADER), f"{path} is missing compact ZTAgent header"


def test_pyproject_carries_author_attribution() -> None:
    content = Path("pyproject.toml").read_text(encoding="utf-8")
    for expected in ATTRIBUTION:
        assert expected in content, f"pyproject.toml is missing {expected}"


def test_documents_carry_author_attribution() -> None:
    files = [Path("README.md"), Path("SECURITY.md"), Path("AUTHORS.md"), Path("NOTICE")]
    files.extend(Path("docs").rglob("*.md"))
    brand = "https://ztagent.ai"

    for path in files:
        content = path.read_text(encoding="utf-8")
        for expected in ATTRIBUTION:
            assert expected in content, f"{path} is missing {expected}"
        assert brand in content, f"{path} is missing {brand}"
