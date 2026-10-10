#!/usr/bin/env bash
# Start the localhost website, or use --cli for a terminal demonstration.
set -e
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python "$project_dir/main.py" "$@"
