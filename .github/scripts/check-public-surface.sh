#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT

manifest_entries() {
  awk '!/^[[:space:]]*(#|$)/ { print }' "$1"
}

policy_entries="$temporary_directory/policy"
surface_entries="$temporary_directory/surface"
expected_entries="$temporary_directory/expected"
tracked_entries="$temporary_directory/tracked"

manifest_entries PUBLIC_ALLOWLIST | LC_ALL=C sort > "$policy_entries"
manifest_entries PUBLIC_SURFACE | LC_ALL=C sort > "$surface_entries"

if LC_ALL=C uniq -d "$policy_entries" | grep -q .; then
  fail 'PUBLIC_ALLOWLIST contains duplicate entries'
fi

if LC_ALL=C uniq -d "$surface_entries" | grep -q .; then
  fail 'PUBLIC_SURFACE contains duplicate entries'
fi

if LC_ALL=C comm -12 "$policy_entries" "$surface_entries" | grep -q .; then
  fail 'PUBLIC_ALLOWLIST and PUBLIC_SURFACE overlap'
fi

LC_ALL=C cat "$policy_entries" "$surface_entries" | LC_ALL=C sort > "$expected_entries"
git ls-files | LC_ALL=C sort > "$tracked_entries"

if ! cmp -s "$expected_entries" "$tracked_entries"; then
  fail 'tracked tree does not match PUBLIC_ALLOWLIST and PUBLIC_SURFACE'
fi

while IFS=$'\t' read -r metadata _path; do
  mode=${metadata%% *}
  case "$mode" in
    100644|100755) ;;
    *) fail "unsupported tracked mode: $mode" ;;
  esac
done < <(git ls-files -s)

tracked_blob_paths="$temporary_directory/tracked-blob-paths"
tracked_blob="$temporary_directory/tracked-blob"
workstation_path_pattern='(^|[^[:alnum:]_.-])(/[U]sers/[^/]+/|/[h]ome/[^/]+/|[[:alpha:]]:([/\\]+)[U]sers([/\\]+)[^/\\]+([/\\]+))'

if ! git ls-files -z > "$tracked_blob_paths" 2>/dev/null; then
  fail 'cannot enumerate tracked public files for workstation-path scan'
fi

while IFS= read -r -d '' tracked_path; do
  if ! git show "HEAD:$tracked_path" > "$tracked_blob" 2>/dev/null; then
    fail 'cannot read tracked public blob for workstation-path scan'
  fi

  if LC_ALL=C grep -a -E -q "$workstation_path_pattern" "$tracked_blob" 2>/dev/null; then
    fail 'tracked public file contains a developer workstation path'
  else
    workstation_path_scan_status=$?
    if test "$workstation_path_scan_status" -ne 1; then
      fail 'cannot scan tracked public files for developer workstation paths'
    fi
  fi
done < "$tracked_blob_paths"

shopt -s nullglob
# This gate intentionally accepts only a simple block-YAML subset. Reject YAML
# syntax that can disguise mapping keys before the deliberately line-oriented
# action-pin check. Block scalars are outside this subset because their bodies
# can hide structural-looking lines from a lexical scanner. GitHub expressions
# are scalar values and may contain braces or YAML indicator characters.
explicit_mapping_key_pattern="(^|[[:space:]-])\\?([[:space:]]|$)"
tag_pattern="(^|[[:space:]:,-])!"
anchor_alias_pattern="(^|[[:space:]:,-])[&*][^[:space:]]"
block_scalar_header_pattern=":[[:space:]]*[|>][0-9+-]*[[:space:]]*$"
uses_key_pattern=$'(["\\\']uses["\\\']|uses)'
uses_line_pattern="^[[:space:]]*(-[[:space:]]*)?${uses_key_pattern}[[:space:]]*:"
uses_pin_pattern="${uses_line_pattern}[[:space:]]*[^[:space:]@]+@[[:xdigit:]]{40}([[:space:]]*(#.*)?)?$"
for workflow in .github/workflows/*.yml .github/workflows/*.yaml; do
  while IFS= read -r workflow_line || [[ -n "$workflow_line" ]]; do
    if [[ -z "${workflow_line//[[:space:]]/}" ]]; then
      continue
    fi

    if [[ "$workflow_line" =~ ^[[:space:]]*# ]]; then
      continue
    fi

    structural_line=$workflow_line
    if [[ "$structural_line" =~ ^(.*)[[:space:]]+#.*$ ]]; then
      structural_line=${BASH_REMATCH[1]}
    fi

    while [[ "$structural_line" == *'${{'*'}}'* ]]; do
      expression_prefix=${structural_line%%'${{'*}
      expression_suffix=${structural_line#*'${{'}
      expression_suffix=${expression_suffix#*'}}'}
      structural_line=${expression_prefix}${expression_suffix}
    done

    if [[ "$structural_line" =~ $block_scalar_header_pattern ]]; then
      fail "unsupported YAML block scalar in $workflow: $workflow_line"
    fi

    case "$structural_line" in
      *'{'*|*'}'*|*'['*|*']'*|*'\'*)
        fail "unsupported non-canonical YAML in $workflow: $workflow_line"
        ;;
    esac
    if [[ "$structural_line" =~ $explicit_mapping_key_pattern ]]; then
      fail "unsupported explicit YAML mapping in $workflow: $workflow_line"
    fi
    if [[ "$structural_line" =~ $tag_pattern ]] ||
       [[ "$structural_line" =~ $anchor_alias_pattern ]]; then
      fail "unsupported non-canonical YAML in $workflow: $workflow_line"
    fi
    if [[ "$workflow_line" =~ $uses_line_pattern ]] && ! [[ "$workflow_line" =~ $uses_pin_pattern ]]; then
      fail "unpinned action in $workflow: $workflow_line"
    fi
  done < "$workflow"
done
