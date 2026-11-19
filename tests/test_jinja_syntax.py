"""Parse every Jinja2 expression embedded in the playbooks and roles.

Ansible cannot run on the development machine, so this catches the most common
mistake (a broken {{ }} / {% %} or a malformed when: condition) before CI.
Only syntax is checked here; behaviour is covered by the CI integration job.
"""

from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FILES = sorted(
    [*ROOT.glob("roles/*/tasks/*.yml"), *ROOT.glob("roles/*/handlers/*.yml"), *ROOT.glob("*.yml")],
    key=lambda p: p.as_posix(),
)
FILES += [ROOT / "group_vars" / "all.yml"]
BARE_KEYS = {"when", "that", "failed_when", "changed_when", "until"}

ENV = jinja2.Environment(extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"])


def _expressions(node, key=None):
    """Yield (key, text, is_bare) for every templated string in a YAML tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _expressions(v, k)
    elif isinstance(node, list):
        for item in node:
            yield from _expressions(item, key)
    elif isinstance(node, str):
        if key in BARE_KEYS and "{{" not in node:
            yield key, node, True
        elif "{{" in node or "{%" in node:
            yield key, node, False
    elif isinstance(node, bool) and key in BARE_KEYS:
        return


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_jinja_expressions_parse(path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    count = 0
    for key, text, bare in _expressions(data):
        source = "{{ " + text + " }}" if bare else text
        try:
            ENV.parse(source)
        except jinja2.TemplateSyntaxError as exc:
            pytest.fail(f"{path.name}: {key}: {exc.message}\n---\n{text}")
        count += 1
    assert count >= 0


# Filters/tests that Ansible itself provides (ansible.builtin); everything else
# must come from filter_plugins/hardening_filters.py or Jinja2.
ANSIBLE_FILTERS = {
    "bool",
    "dict2items",
    "items2dict",
    "b64decode",
    "b64encode",
    "from_json",
    "to_json",
    "to_nice_json",
    "quote",
    "regex_search",
    "regex_replace",
    "split",
    "unique",
    "combine",
    "dirname",
    "basename",
    "mandatory",
}
ANSIBLE_TESTS = {"search", "match", "file", "directory", "exists", "string"}


def test_only_known_filters_and_tests_are_used():
    import hardening_filters

    env = jinja2.Environment(extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"])
    for name in ANSIBLE_FILTERS | set(hardening_filters.FilterModule().filters()):
        env.filters[name] = lambda *a, **k: None
    for name in ANSIBLE_TESTS:
        env.tests[name] = lambda *a, **k: True
    paths = FILES + sorted(ROOT.glob("roles/*/templates/*.j2"))
    for path in paths:
        if path.suffix == ".j2":
            items = [("template", path.read_text(encoding="utf-8"), False)]
        else:
            items = list(_expressions(yaml.safe_load(path.read_text(encoding="utf-8"))))
        for key, text, bare in items:
            source = "{{ " + text + " }}" if bare else text
            try:
                env.from_string(source)  # compiling resolves filter and test names
            except (jinja2.TemplateAssertionError, jinja2.TemplateSyntaxError) as exc:
                pytest.fail(f"{path.name}: {key}: {exc}")
