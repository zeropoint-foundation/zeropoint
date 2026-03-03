#!/usr/bin/env bash
# ============================================================================
# ZeroPoint Shim Generator
# ============================================================================
#
# Usage: generate-shim.sh <tool_name> <actor_type>
#
# Creates a PATH-priority wrapper shim in ~/.zeropoint/bin/ for the given tool.
# Actor types: codex (AI coding assistants), agent (autonomous agents)
#
# Examples:
#   generate-shim.sh cursor codex
#   generate-shim.sh aider codex
#   generate-shim.sh copilot codex
# ============================================================================

set -euo pipefail

TOOL_NAME="${1:?Usage: generate-shim.sh <tool_name> <actor_type>}"
ACTOR="${2:-codex}"
SHIM_DIR="$HOME/.zeropoint/bin"
TEMPLATE_DIR="$(cd "$(dirname "$0")" && pwd)"

# Validate actor type
case "$ACTOR" in
  human|codex|agent) ;;
  *)
    echo "Error: actor must be human, codex, or agent (got: $ACTOR)" >&2
    exit 1
    ;;
esac

# Check that the real tool exists
if ! command -v "$TOOL_NAME" &>/dev/null; then
  echo "Warning: '$TOOL_NAME' not found in PATH. Shim will be created but may not work until the tool is installed." >&2
fi

# Create shim directory
mkdir -p "$SHIM_DIR"

# Generate shim from template
SHIM_PATH="$SHIM_DIR/$TOOL_NAME"

sed -e "s/{{TOOL_NAME}}/$TOOL_NAME/g" \
    -e "s/{{ACTOR}}/$ACTOR/g" \
    "$TEMPLATE_DIR/wrapper-template.sh" > "$SHIM_PATH"

chmod 755 "$SHIM_PATH"

echo "Created wrapper shim: $SHIM_PATH (actor: $ACTOR)"
echo "The real '$TOOL_NAME' binary will be resolved at runtime from PATH."
