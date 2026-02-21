"""
Phantom Rectifier — CloudFormation IaC Reconciliation

Reads the Phantom analysis report (analysis-output.json) together with the
safe-state and drifted CloudFormation templates and applies each per-change
recommendation to produce a single rectified YAML template.

Decision logic per change:
  revert     → use safe-state value  (undo the console drift)
  legitimize → use drifted value     (accept the change into version control)
  refactor   → use refactored_value  (AI-recommended optimised middle-ground)

Supports three property-path formats:
  - Simple:    "InstanceType"
  - List-index:"SecurityGroupIngress[2]"  (add / remove list elements)
  - Tag-map:   "Tags[ManagedBy]"          (key-value lookup inside Tags list)

Can be run standalone:
    python rectifier.py

Or imported and called from analyzer.py:
    from rectifier import rectify
"""

import copy
import json
import re
import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Paths (all relative to this file's directory)
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).parent
_DUMMY_DATA = _ROOT / "dummy-data"

DEFAULT_ANALYSIS_PATH = _ROOT / "analysis-output.json"
DEFAULT_SAFE_STATE_PATH = _DUMMY_DATA / "safe-state-template.yaml"
DEFAULT_DRIFTED_PATH = _DUMMY_DATA / "drifted-template.yml"
DEFAULT_OUTPUT_PATH = _ROOT / "rectified-template.yaml"

# ---------------------------------------------------------------------------
# CloudFormation-aware YAML loader / dumper
# Preserves intrinsic tags: !Ref, !GetAtt, !Select, !Sub, etc.
# ---------------------------------------------------------------------------

class _CFNode:
    """
    Wraps a CloudFormation intrinsic function (e.g. !Ref, !GetAtt).
    Uses a regular class (not str subclass) so deepcopy works reliably.
    """
    __slots__ = ("cf_tag", "value")

    def __init__(self, cf_tag: str, value):
        self.cf_tag = cf_tag
        self.value = value

    def __deepcopy__(self, memo):
        import copy
        return _CFNode(self.cf_tag, copy.deepcopy(self.value, memo))

    def __repr__(self):
        return f"_CFNode({self.cf_tag!r}, {self.value!r})"


class _CFLoader(yaml.SafeLoader):
    pass


class _CFDumper(yaml.Dumper):
    pass


def _node_constructor(cf_tag: str):
    def _fn(loader, node):
        if isinstance(node, yaml.ScalarNode):
            val = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            val = loader.construct_sequence(node, deep=True)
        else:
            val = loader.construct_mapping(node, deep=True)
        return _CFNode(cf_tag, val)
    return _fn


def _node_representer(dumper, data: _CFNode):
    val = data.value
    if isinstance(val, str):
        return dumper.represent_scalar(data.cf_tag, val)
    elif isinstance(val, list):
        return dumper.represent_sequence(data.cf_tag, val)
    else:
        return dumper.represent_mapping(data.cf_tag, val)


_CF_TAGS = [
    "!Ref", "!GetAtt", "!Sub", "!Select", "!GetAZs",
    "!Join", "!If", "!Not", "!And", "!Or", "!Equals",
    "!Base64", "!Cidr", "!FindInMap", "!ImportValue",
    "!Split", "!Transform",
]
for _t in _CF_TAGS:
    _CFLoader.add_constructor(_t, _node_constructor(_t))

_CFDumper.add_representer(_CFNode, _node_representer)


def load_template(path: Path) -> dict:
    with open(path) as f:
        return yaml.load(f, Loader=_CFLoader)


def render_template(data: dict) -> str:
    """Serialise a template dict to a YAML string (no file I/O)."""
    return yaml.dump(data, Dumper=_CFDumper, default_flow_style=False, allow_unicode=True)


def save_template(data: dict, path: Path) -> None:
    """Write a template dict to a YAML file on disk."""
    with open(path, "w") as f:
        f.write(render_template(data))


def load_analysis(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Property-path helpers
# ---------------------------------------------------------------------------

# Matches "Tags[SomeKey]" — a tag lookup
_TAG_PATH_RE = re.compile(r"^Tags\[(.+)\]$")
# Matches "SomeProp[0]" — a list index access
_LIST_PATH_RE = re.compile(r"^(.+)\[(\d+)\]$")


def _get_resource_props(template: dict, logical_id: str) -> dict:
    return template["Resources"][logical_id]["Properties"]


def _get_simple(props: dict, key: str):
    """Return props[key], or None if missing."""
    return props.get(key)


def _set_simple(props: dict, key: str, value) -> None:
    props[key] = value


def _del_simple(props: dict, key: str) -> None:
    props.pop(key, None)


def _tags_as_dict(tags: list) -> dict:
    """Convert CloudFormation Tags list → {Key: Value}."""
    return {t["Key"]: t["Value"] for t in tags}


def _dict_to_tags(tags_dict: dict) -> list:
    """Convert {Key: Value} → CloudFormation Tags list."""
    return [{"Key": k, "Value": v} for k, v in tags_dict.items()]


def _get_tag_value(props: dict, tag_key: str):
    tags = _tags_as_dict(props.get("Tags", []))
    return tags.get(tag_key)


def _set_tag_value(props: dict, tag_key: str, value) -> None:
    tags = _tags_as_dict(props.get("Tags", []))
    tags[tag_key] = value
    props["Tags"] = _dict_to_tags(tags)


def _del_tag(props: dict, tag_key: str) -> None:
    tags = _tags_as_dict(props.get("Tags", []))
    tags.pop(tag_key, None)
    props["Tags"] = _dict_to_tags(tags)


def _get_list_element(props: dict, list_key: str, index: int):
    lst = props.get(list_key, [])
    return lst[index] if index < len(lst) else None


def _set_list_element(props: dict, list_key: str, index: int, value) -> None:
    lst = props.setdefault(list_key, [])
    while len(lst) <= index:
        lst.append(None)
    lst[index] = value


def _del_list_element(props: dict, list_key: str, index: int) -> None:
    """Remove element at index (used for revert of property_added)."""
    lst = props.get(list_key, [])
    if index < len(lst):
        lst.pop(index)


# ---------------------------------------------------------------------------
# Core: apply a single change recommendation
# ---------------------------------------------------------------------------

REVERT_TEXT = {
    "revert": "REVERTED",
    "legitimize": "LEGITIMIZED",
    "refactor": "REFACTORED",
}


def _apply_change(
    result_props: dict,
    safe_props: dict,
    drifted_props: dict,
    change: dict,
) -> str:
    """
    Apply one change recommendation to result_props (mutated in place).
    Returns a short summary string for logging.
    """
    path: str = change["property_path"]
    rec: str = change["recommendation"]
    old_val = change["old_value"]    # safe-state value
    new_val = change["new_value"]    # drifted value
    refactored = change.get("refactored_value")

    # ---- Determine what the final value should be -------------------------
    if rec == "revert":
        final = old_val          # restore safe-state
        is_delete = (old_val is None)
    elif rec == "legitimize":
        final = new_val          # accept drifted change
        is_delete = (new_val is None)
    elif rec == "refactor":
        final = refactored       # optimised middle-ground
        is_delete = (refactored is None)
    else:
        return f"  ⚠ Unknown recommendation '{rec}', skipping"

    # ---- Dispatch by path type -------------------------------------------
    tag_match = _TAG_PATH_RE.match(path)
    list_match = _LIST_PATH_RE.match(path)

    if tag_match:
        # Tags[SomeKey]
        tag_key = tag_match.group(1)
        if is_delete:
            _del_tag(result_props, tag_key)
            return f"  {REVERT_TEXT[rec]}: Tags[{tag_key}] → (removed)"
        else:
            _set_tag_value(result_props, tag_key, final)
            return f"  {REVERT_TEXT[rec]}: Tags[{tag_key}] → {final!r}"

    elif list_match:
        # SomeProp[N]
        list_key = list_match.group(1)
        index = int(list_match.group(2))

        if is_delete:
            # old_value was None → element was added in drift → revert means remove it
            _del_list_element(result_props, list_key, index)
            return f"  {REVERT_TEXT[rec]}: {list_key}[{index}] → (removed)"
        else:
            _set_list_element(result_props, list_key, index, final)
            return f"  {REVERT_TEXT[rec]}: {list_key}[{index}] → {final!r}"

    else:
        # Simple property key
        if is_delete:
            _del_simple(result_props, path)
            return f"  {REVERT_TEXT[rec]}: {path} → (removed)"
        else:
            _set_simple(result_props, path, final)
            return f"  {REVERT_TEXT[rec]}: {path}: {old_val!r} → {final!r}"


# ---------------------------------------------------------------------------
# Top-level rectifier
# ---------------------------------------------------------------------------

def apply_recommendations(
    safe_state: dict,
    drifted_state: dict,
    analysis: dict,
) -> dict:
    """
    Merge safe-state and drifted templates according to analysis recommendations.

    Strategy:
      - Start with the safe-state template as the base.
      - For each drift change apply the recommendation (revert / legitimize / refactor).
      - This naturally handles "no changes outside the diff" correctly since
        un-drifted resources are already identical in both templates.

    Returns a new dict (deep-copied; originals are not mutated).
    """
    result = copy.deepcopy(safe_state)

    changes = analysis.get("changes", [])
    print(f"\n5/5  Rectifying CloudFormation template ({len(changes)} changes)...\n")

    by_resource: dict[str, list] = {}
    for change in changes:
        rid = change["resource_logical_id"]
        by_resource.setdefault(rid, []).append(change)

    for logical_id, resource_changes in by_resource.items():
        print(f"  [{logical_id}]")
        try:
            result_props = _get_resource_props(result, logical_id)
            safe_props = _get_resource_props(safe_state, logical_id)
            drifted_props = _get_resource_props(drifted_state, logical_id)
        except KeyError:
            print(f"  ⚠ Resource '{logical_id}' not found in template, skipping")
            continue

        for change in resource_changes:
            summary = _apply_change(result_props, safe_props, drifted_props, change)
            cid = change["change_id"]
            rec = change["recommendation"].upper()
            print(f"    {cid} [{rec}]{summary[summary.index(':'):]}")

    return result


def rectify(
    analysis: dict | None = None,
    # Accept either a pre-parsed dict or a file path for both templates.
    # analyzer.py passes dicts directly (loaded from diff-output.json);
    # standalone mode falls back to reading the YAML files from disk.
    safe_state: dict | None = None,
    drifted_state: dict | None = None,
    safe_state_path: Path = DEFAULT_SAFE_STATE_PATH,
    drifted_path: Path = DEFAULT_DRIFTED_PATH,
    analysis_path: Path = DEFAULT_ANALYSIS_PATH,
) -> str:
    """
    Orchestrate the full rectification pipeline.

    Templates can be provided as pre-parsed dicts (from analyzer.py) or
    resolved from file paths (standalone mode). Analysis dict takes priority
    over analysis_path.

    Returns the rectified CloudFormation template as a YAML string.
    No files are written to disk.
    """
    if analysis is None:
        print(f"  → Loading analysis from {analysis_path}")
        analysis = load_analysis(analysis_path)

    if safe_state is None:
        safe_state = load_template(safe_state_path)
    if drifted_state is None:
        drifted_state = load_template(drifted_path)

    rectified = apply_recommendations(safe_state, drifted_state, analysis)

    # Update the Description field to reflect rectified state
    original_desc = rectified.get("Description", "")
    if "(Rectified)" not in original_desc:
        rectified["Description"] = original_desc.replace(
            "(Safe State)", "(Rectified)"
        ).replace(
            "Safe State", "Rectified"
        ) + " — Rectified by Phantom"

    return render_template(rectified)


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def _standalone():
    print("\n🔧 Phantom Rectifier — Applying reconciliation recommendations...\n")
    print(f"  Analysis:    {DEFAULT_ANALYSIS_PATH}")
    print(f"  Safe state:  {DEFAULT_SAFE_STATE_PATH}")
    print(f"  Drifted:     {DEFAULT_DRIFTED_PATH}")
    print()

    try:
        yaml_str = rectify()
    except FileNotFoundError as e:
        print(f"\n✗ File not found: {e}")
        print("  Tip: run analyzer.py first to generate analysis-output.json")
        sys.exit(1)

    print("=" * 60)
    print("  RECTIFIED TEMPLATE (YAML)")
    print("=" * 60)
    print(yaml_str)


if __name__ == "__main__":
    _standalone()
