[[ "${CODEQL_EXTRACTOR_CPP_AUTOBUILD_VERBOSE:-}" = "true" || "${RUNNER_DEBUG:-}" = "1" ]] && set -x

function log() {
  echo "cpp/autobuilder: $*" >&2
}
