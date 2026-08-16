#!/bin/sh

set -eu

exec "${CODEQL_DIST}/codeql" database index-files \
	--prune="**/*.testproj" \
	--include-extension=.yml \
	--include-extension=.yaml \
	--size-limit=5m \
	--language=yaml \
	--working-dir=. "$CODEQL_EXTRACTOR_YAML_WIP_DATABASE"
