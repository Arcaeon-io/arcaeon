"""L1-03 / L1-04 / L1-06: the release workflow, read as YAML.

.github/workflows/release.yml publishes arcaeon with PyPI Trusted Publishing
(GitHub OIDC), so PEP 740 attestations ride along and no API token exists to
leak. These tests read the file only. They need no PyPI publisher, no GitHub
environment and no network: those two settings are the owner's (docs/RELEASE.md).
"""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parent.parent
WF_PATH = ROOT / ".github" / "workflows" / "release.yml"
PUBLISH_ACTION = "pypa/gh-action-pypi-publish"
TEST_UPLOAD = "https://test.pypi.org/legacy/"
PUBLISH_JOBS = {"publish-pypi", "publish-testpypi"}


@pytest.fixture(scope="module")
def text():
    return WF_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def wf(text):
    return yaml.safe_load(text)


def _on(wf):
    # PyYAML (YAML 1.1) reads the bare key `on` as the boolean True.
    return wf.get("on", wf.get(True))


def _steps(job):
    return job.get("steps", [])


def _runs(job):
    return "\n".join(s.get("run", "") for s in _steps(job))


def _uses(job, prefix):
    return [s for s in _steps(job) if str(s.get("uses", "")).startswith(prefix)]


def _needs(job):
    n = job.get("needs", [])
    return [n] if isinstance(n, str) else list(n)


def test_triggers_are_v_tags_and_a_dispatch_choice(wf):
    on = _on(wf)
    assert on["push"]["tags"] == ["v*"]
    assert set(on["push"]) == {"tags"}, "only tag pushes publish, not branch pushes"
    target = on["workflow_dispatch"]["inputs"]["target"]
    assert target["type"] == "choice"
    assert set(target["options"]) == {"testpypi", "pypi"}
    assert target.get("default") == "testpypi", "a hand-started run rehearses unless told otherwise"


def test_top_level_permissions_are_read_only(wf):
    perms = wf.get("permissions")
    assert isinstance(perms, dict), "set top-level permissions explicitly"
    assert all(v in ("read", "none") for v in perms.values()), perms


def test_oidc_token_only_on_the_publish_jobs(wf):
    with_oidc = {name for name, job in wf["jobs"].items()
                 if (job.get("permissions") or {}).get("id-token") == "write"}
    assert with_oidc == PUBLISH_JOBS
    for name in PUBLISH_JOBS:
        assert wf["jobs"][name]["permissions"] == {"id-token": "write"}, name


def test_every_job_sets_its_own_permissions_and_only_publish_writes(wf):
    for name, job in wf["jobs"].items():
        perms = job.get("permissions")
        assert isinstance(perms, dict), f"{name} has no explicit permissions"
        writes = {k for k, v in perms.items() if v == "write"}
        if name in PUBLISH_JOBS:
            assert writes == {"id-token"}, (name, writes)
        else:
            assert not writes, f"{name} must be read-only, has {writes}"


def test_environment_names(wf):
    def env_name(job):
        env = job.get("environment")
        return env["name"] if isinstance(env, dict) else env
    assert env_name(wf["jobs"]["publish-pypi"]) == "pypi"
    assert env_name(wf["jobs"]["publish-testpypi"]) == "testpypi"
    for name, job in wf["jobs"].items():
        if name not in PUBLISH_JOBS:
            assert job.get("environment") is None, name


def test_no_token_or_password_anywhere(text):
    low = text.lower()
    for needle in ("password:", "secrets.", "api_token", "pypi_token", "__token__", "user:"):
        assert needle not in low, f"release.yml mentions {needle!r}; Trusted Publishing needs none"


def test_publish_steps_use_the_pypa_action_with_attestations_and_no_credentials(wf):
    for name in PUBLISH_JOBS:
        steps = _uses(wf["jobs"][name], PUBLISH_ACTION)
        assert len(steps) == 1, name
        w = steps[0].get("with", {})
        assert w.get("attestations") is True, f"{name}: attestations must be true"
        assert not {"password", "user", "username"} & set(w), name
        assert w.get("packages-dir") == "dist/", name


def test_publish_jobs_run_no_repo_code(wf):
    """The jobs holding the OIDC token download the built files and upload them.
    They do not check out the repo or run its scripts."""
    for name in PUBLISH_JOBS:
        job = wf["jobs"][name]
        assert not _uses(job, "actions/checkout"), name
        assert not _runs(job).strip(), f"{name} runs shell steps"
        assert "build" in _needs(job)
        assert _uses(job, "actions/download-artifact"), name


def test_build_job_builds_both_kinds_and_runs_twine_check_strict(wf):
    runs = _runs(wf["jobs"]["build"])
    assert "python -m build" in runs
    assert "--sdist" not in runs and "--wheel" not in runs, "build both, sdist and wheel"
    assert "twine check --strict dist/*" in runs


def test_build_uploads_dist_and_the_hash_manifest(wf):
    build = wf["jobs"]["build"]
    names = {s["with"]["name"] for s in _uses(build, "actions/upload-artifact")}
    assert {"dist", "release-manifest"} <= names
    assert "verify_published.py manifest" in _runs(build)


def test_version_guard_runs_before_the_build(wf):
    steps = _steps(wf["jobs"]["build"])
    runs = [s.get("run", "") for s in steps]
    guard = next(i for i, r in enumerate(runs) if "release_guard.py" in r)
    build = next(i for i, r in enumerate(runs) if "python -m build" in r)
    assert guard < build
    assert "GITHUB_REF_NAME" in str(steps[guard].get("env", {})) or "GITHUB_REF_NAME" in runs[guard]


def test_dispatch_input_selects_the_publish_job(wf):
    pypi_if = wf["jobs"]["publish-pypi"]["if"]
    test_if = wf["jobs"]["publish-testpypi"]["if"]
    assert "'pypi'" in pypi_if and "'testpypi'" in test_if
    assert "needs.build.outputs.target" in pypi_if and "needs.build.outputs.target" in test_if


def test_testpypi_upload_url_only_in_the_testpypi_job(wf):
    for name, job in wf["jobs"].items():
        dumped = yaml.safe_dump(job)
        if name == "publish-testpypi":
            step = _uses(job, PUBLISH_ACTION)[0]
            assert step["with"].get("repository-url") == TEST_UPLOAD
        else:
            assert TEST_UPLOAD not in dumped, name
    assert "repository-url" not in yaml.safe_dump(wf["jobs"]["publish-pypi"])


def test_verify_job_needs_publish_and_checks_hashes(wf):
    verify = wf["jobs"]["verify"]
    assert PUBLISH_JOBS <= set(_needs(verify))
    assert "build" in _needs(verify)
    runs = _runs(verify)
    assert "verify_published.py fetch" in runs
    assert "python -m venv" in runs, "verify downloads from a clean venv"
    names = {s["with"]["name"] for s in _uses(verify, "actions/download-artifact")}
    assert "release-manifest" in names
    cond = verify["if"]
    assert "success" in cond and "failure()" in cond


def test_third_party_actions_are_pinned(wf):
    for name, job in wf["jobs"].items():
        for s in _steps(job):
            if "uses" in s:
                ref = s["uses"].split("@", 1)
                assert len(ref) == 2 and ref[1], f"{name}: unpinned {s['uses']}"
                assert ref[1] not in ("main", "master", "latest"), f"{name}: floating {s['uses']}"


def test_release_doc_names_the_two_owner_settings_to_match_the_workflow(wf):
    doc = (ROOT / "docs" / "RELEASE.md").read_text(encoding="utf-8")
    section = doc.split("## Two settings that are the owner's", 1)[1].split("\n## ", 1)[0]
    for needle in ("Add a new publisher", "`Arcaeon-io`", "`arcaeon`", f"`{WF_PATH.name}`",
                   "environment `pypi`", "environment `testpypi`", "Settings -> Environments"):
        assert needle in section, needle
    assert "## Limits" in doc
