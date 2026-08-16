#!/bin/sh

set -eu

exec "${CODEQL_JAVA_HOME}/bin/java" \
    -jar "$CODEQL_EXTRACTOR_YAML_ROOT/tools/yaml-extractor.jar" \
        --fileList="$1" \
        --sourceArchiveDir="$CODEQL_EXTRACTOR_YAML_SOURCE_ARCHIVE_DIR" \
        --outputDir="$CODEQL_EXTRACTOR_YAML_TRAP_DIR"
