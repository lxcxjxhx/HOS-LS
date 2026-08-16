#!/bin/bash

set -eu

function check_size_limit {
  "$CODEQL_DIST/codeql" resolve files \
      --total-size-limit 50m \
      --include-extension=.xml \
      --include-extension=.wsdd \
      --also-match-lgtm-index-filters \
      . >/dev/null 2>&1
}

function index_by_name {
  "$CODEQL_DIST/codeql" database index-files \
      --include "**/AndroidManifest.xml" \
      --include "**/pom.xml" \
      --include "**/struts.xml" \
      --include "**/web.xml" \
      --also-match-lgtm-index-filters \
      --size-limit 10m \
      --language xml \
      -- \
      "$CODEQL_EXTRACTOR_JAVA_WIP_DATABASE"
}

function index_smart_mode {
  export CODEQL_EXTRACTOR_XML_PRIMARY_TAGS="faceted-project project plugin idea-plugin beans struts web-app module ui:UiBinder persistence deployment undeployment"
  "$CODEQL_DIST/codeql" database index-files \
      --include-extension=.xml \
      --include-extension=.wsdd \
      --also-match-lgtm-index-filters \
      --size-limit 10m \
      --language xml \
      -- \
      "$CODEQL_EXTRACTOR_JAVA_WIP_DATABASE"
}

function index_all_files {
  "$CODEQL_DIST/codeql" database index-files \
      --include-extension=.xml \
      --include-extension=.wsdd \
      --also-match-lgtm-index-filters \
      --size-limit 10m \
      --language xml \
      -- \
      "$CODEQL_EXTRACTOR_JAVA_WIP_DATABASE"
}

if [ "${LGTM_INDEX_XML_MODE:-default}" == "default" ]; then
  TOO_BIG_MESSAGE="More than 50MB of XML files found: only files with well-known names (e.g. pom.xml) will be extracted in order to save space. Set LGTM_INDEX_XML_MODE to override this behaviour."
  (check_size_limit && index_all_files) || (echo "$TOO_BIG_MESSAGE" && index_by_name)
elif [ "${LGTM_INDEX_XML_MODE}" == "byname" ]; then
  index_by_name
elif [ "${LGTM_INDEX_XML_MODE}" == "smart" ]; then
  index_smart_mode
elif [ "${LGTM_INDEX_XML_MODE}" == "all" ]; then
  index_all_files
fi

if [ "${LGTM_INDEX_PROPERTIES_FILES:-true}" == "true" ]; then
"$CODEQL_DIST/codeql" database index-files \
    --include-extension=.properties \
    --also-match-lgtm-index-filters \
    --size-limit=5m \
    --language properties \
    -- \
    "$CODEQL_EXTRACTOR_JAVA_WIP_DATABASE"
fi
