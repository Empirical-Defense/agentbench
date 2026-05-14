#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTIVE_FILE="$ROOT_DIR/frameworks/crosswalks/active_versions.env"
CROSSWALK_ROOT="$ROOT_DIR/frameworks/crosswalks/owasp_llm_top10"
DOCS_ROOT="$ROOT_DIR/frameworks/owas_top_10_llm"

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 1.2"
  exit 1
fi

TARGET_VERSION="$1"
TARGET_DIR="${TARGET_VERSION//./_}"
TARGET_DOCS_DIR="$DOCS_ROOT/$TARGET_DIR"
TARGET_MAP_DIR="$CROSSWALK_ROOT/$TARGET_DIR"
TARGET_MAP_FILE="$TARGET_MAP_DIR/aiuc_to_owasp_llm_top10.csv"

if [[ ! -d "$TARGET_DOCS_DIR" ]]; then
  echo "Error: OWASP docs directory not found: $TARGET_DOCS_DIR"
  echo "Add docs first, then rerun."
  exit 1
fi

if [[ ! -f "$ACTIVE_FILE" ]]; then
  echo "Error: Active version file not found: $ACTIVE_FILE"
  exit 1
fi

# shellcheck source=/dev/null
source "$ACTIVE_FILE"
CURRENT_VERSION="${OWASP_LLM_TOP10_ACTIVE_VERSION:-}"
if [[ -z "$CURRENT_VERSION" ]]; then
  echo "Error: OWASP_LLM_TOP10_ACTIVE_VERSION is not set in $ACTIVE_FILE"
  exit 1
fi

CURRENT_DIR="${CURRENT_VERSION//./_}"
CURRENT_MAP_FILE="$CROSSWALK_ROOT/$CURRENT_DIR/aiuc_to_owasp_llm_top10.csv"

mkdir -p "$TARGET_MAP_DIR"

if [[ ! -f "$TARGET_MAP_FILE" ]]; then
  if [[ -f "$CURRENT_MAP_FILE" ]]; then
    cp "$CURRENT_MAP_FILE" "$TARGET_MAP_FILE"
    awk -F',' -v OFS=',' -v target="$TARGET_VERSION" '
      NR==1 { print; next }
      { $5=target; print }
    ' "$TARGET_MAP_FILE" > "$TARGET_MAP_FILE.tmp"
    mv "$TARGET_MAP_FILE.tmp" "$TARGET_MAP_FILE"
    echo "Created new mapping from $CURRENT_VERSION -> $TARGET_VERSION"
  else
    cat > "$TARGET_MAP_FILE" <<'CSV'
aiuc_control_id,aiuc_control_family,owasp_llm_risk_id,owasp_llm_risk_title,owasp_llm_version,mapping_strength,mapping_rationale
CSV
    echo "Created empty mapping template for $TARGET_VERSION"
  fi
fi

sed -i.bak -E "s/^OWASP_LLM_TOP10_ACTIVE_VERSION=.*/OWASP_LLM_TOP10_ACTIVE_VERSION=$TARGET_VERSION/" "$ACTIVE_FILE"
rm -f "$ACTIVE_FILE.bak"

echo "Active OWASP LLM Top 10 version set to $TARGET_VERSION"
echo "Active mapping file: $TARGET_MAP_FILE"
echo "Review and adjust mappings for taxonomy changes before using in production."
