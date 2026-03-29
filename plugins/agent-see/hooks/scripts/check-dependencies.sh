#!/usr/bin/env bash
# Check if agent-see and its dependencies are available

missing=()

if ! command -v agent-see &>/dev/null; then
  missing+=("agent-see CLI not found. Install with: pip install git+https://github.com/Danielfoojunwei/Convert-any-SaaS-application-into-an-Agentic-interface.git")
fi

if ! command -v python3 &>/dev/null; then
  missing+=("Python 3 not found. Agent-See requires Python 3.11+.")
fi

if [ ${#missing[@]} -eq 0 ]; then
  echo "## Agent-See Environment"
  echo ""
  echo "All dependencies available. Ready to convert business surfaces into agent bundles."
  echo ""
  echo "Available commands: convert, launch, plugin, verify"
else
  echo "## Agent-See Environment"
  echo ""
  echo "Missing dependencies detected:"
  echo ""
  for item in "${missing[@]}"; do
    echo "- $item"
  done
  echo ""
  echo "The convert-source skill will attempt auto-installation when triggered."
fi
