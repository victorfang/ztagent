# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

from pathlib import Path

ATTRIBUTION = (
    "Victor Fang",
    "https://VictorFang.com",
    "https://X.com/vicfcs",
    "https://www.linkedin.com/in/drvictorfang",
)


def test_code_and_configuration_carry_author_attribution() -> None:
    files = [
        *Path("src").rglob("*.py"),
        *Path("tests").rglob("*.py"),
        *Path("config").rglob("*.yaml"),
        Path("src/mini_secure_agent/py.typed"),
        Path("app.py"),
        Path("compose.yaml"),
        Path("policies/authz.rego"),
        Path("pyproject.toml"),
        Path(".env.example"),
    ]

    for path in files:
        content = path.read_text(encoding="utf-8")
        for expected in ATTRIBUTION:
            assert expected in content, f"{path} is missing {expected}"


def test_documents_carry_author_attribution() -> None:
    files = [Path("README.md"), Path("SECURITY.md"), Path("AUTHORS.md"), Path("NOTICE")]
    files.extend(Path("docs").rglob("*.md"))

    for path in files:
        content = path.read_text(encoding="utf-8")
        for expected in ATTRIBUTION:
            assert expected in content, f"{path} is missing {expected}"
