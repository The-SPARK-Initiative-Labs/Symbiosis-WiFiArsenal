#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR/wardrive"
exec ./RUN_WARDRIVE.sh
