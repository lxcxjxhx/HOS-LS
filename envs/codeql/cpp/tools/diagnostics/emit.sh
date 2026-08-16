#!/bin/bash -eu

. "$AUTOBUILD_ROOT/lib/log.sh"

# emit json diagnostics taking data from a file named after the ID provided as first argument
# following arguments are interpolated in the format string defined by MARKDOWN_MESSAGE or
# PLAINTEXT_MESSAGE in the file itself

ID=$1
DATA="$(dirname "$0")/$ID"

shift

if [[ ! -f "$DATA" ]]; then
  log "No data file found for diagnostic $ID"
  exit 1
fi

# shellcheck source=/dev/null
source "$DATA"

mkdir -p "$CODEQL_EXTRACTOR_CPP_DIAGNOSTIC_DIR"

log "$SOURCE_NAME."

ATTRS=()
while [[ "$#" != 0 ]]; do
  case "$1" in
  --?*)
    ATTRS+=("\"${1:2}\": $2")
    shift
    shift;;
  --|*)
    break
    ;;
  esac
done

exec >> "$CODEQL_EXTRACTOR_CPP_DIAGNOSTIC_DIR/autobuilder-$$.jsonl"

echo "{"
echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%TZ")\","
echo "  \"source\": {"
echo "    \"id\": \"$SOURCE_ID\","
echo "    \"name\": \"$SOURCE_NAME\","
echo "    \"extractorName\": \"cpp\""
echo "  },"
echo "  \"severity\": \"$SEVERITY\","
# replace newlines in messages with literal '\n' using `${X//$'\n'/\\\\n}`
# replacement `\n` need to be doubly escaped because they are used in `printf`
# shellcheck disable=SC2059
if [[ -n "${MARKDOWN_MESSAGE:-}" ]]; then
  MARKDOWN_MESSAGE=$(printf "$MARKDOWN_MESSAGE" "$@")
  echo "  \"markdownMessage\": \"${MARKDOWN_MESSAGE//$'\n'/\\n}\","
elif [[ -n "${PLAINTEXT_MESSAGE:-}" ]]; then
  PLAINTEXT_MESSAGE=$(printf "$PLAINTEXT_MESSAGE" "$@")
  echo "  \"plaintextMessage\": \"${PLAINTEXT_MESSAGE//$'\n'/\\n}\","
fi
if [[ -n "${HELP_LINKS:-}" ]]; then
  echo "  \"helpLinks\": ["
  echo -n "    \"${HELP_LINKS[0]}\""
  for link in "${HELP_LINKS[@]:1}"; do
    echo -en ",\n    \"$link\""
  done
  echo
  echo "  ],"
fi
echo "  \"visibility\": {"
echo "    \"statusPage\": ${STATUS_PAGE:-true},"
echo "    \"cliSummaryTable\": ${CLI_SUMMARY_TABLE:-true},"
echo "    \"telemetry\": ${TELEMETRY:-true}"
echo -n "  }"
if [[ "${#ATTRS[@]}" != 0 ]]; then
  echo ","
  echo "  \"attributes\": {"
  echo -n "    ${ATTRS[0]}"
  for attr in "${ATTRS[@]:1}"; do
    echo ","
    echo -n "    $attr"
  done
  echo
  echo -n "  }"
fi
echo
echo "}"
