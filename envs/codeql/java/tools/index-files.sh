#!/bin/sh

set -eu

"${CODEQL_EXTRACTOR_JAVA_STANDALONE_JAVA_CMD:-java}" \
  -cp "${CODEQL_EXTRACTOR_JAVA_ROOT}/tools/codeql-java-agent.jar" \
  com.semmle.extractor.java.Extractor \
  "$1" -d "${CODEQL_EXTRACTOR_JAVA_SCRATCH_DIR}/codeql-standalone-build-classes" || exit 0
