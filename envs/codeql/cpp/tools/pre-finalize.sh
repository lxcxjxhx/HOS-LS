#!/bin/bash
"$CODEQL_EXTRACTOR_CPP_ROOT/tools/$CODEQL_PLATFORM/cpp-telemetry"

if [ "${CODEQL_EXTRACTOR_CPP_TRAP_CACHING}" == "true" ]; then
  if [ "${CODEQL_EXTRACTOR_CPP_OPTION_TRAP_CACHE_WRITE}" == "true" ]; then
    mkdir -p "${CODEQL_EXTRACTOR_CPP_OPTION_TRAP_CACHE_DIR:-.}"
    cp -R "${CODEQL_EXTRACTOR_CPP_TRAP_DIR:-.}/tarballs" "${CODEQL_EXTRACTOR_CPP_OPTION_TRAP_CACHE_DIR:-.}/tarballs"
  elif [ "${CODEQL_EXTRACTOR_CPP_OPTION_TRAP_CACHE_WRITE}" == "false" ]; then
    "$CODEQL_EXTRACTOR_CPP_ROOT/tools/$CODEQL_PLATFORM/trap-cache-reader"
  fi
fi
