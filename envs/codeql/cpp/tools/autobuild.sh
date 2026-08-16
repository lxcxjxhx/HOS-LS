#!/bin/bash

set -eu
set -o pipefail

# Directory where the autobuild scripts live.
export AUTOBUILD_ROOT="$CODEQL_EXTRACTOR_CPP_ROOT/tools"

source "$AUTOBUILD_ROOT/lib/log.sh"

# A temporary directory to store intermediate codeql artifacts.
export AUTOBUILD_TMP_DIR="$(mktemp -dt autobuild.XXXXX)"

# some default build environment settings

# Enables verbose build output for CMake >= 3.14
export VERBOSE=1
# disable ccache
export CCACHE_DISABLE=1

source "$AUTOBUILD_ROOT/lib/dirs.sh"
trap cleanup EXIT

if [[ "${CODEQL_EXTRACTOR_CPP_AUTOINSTALL_DEPENDENCIES:-}" == "true" ]]; then
  # this path is shared between deptrace-init and cmake-wrapper called in do-prebuild
  export CODEQL_DEPTRACE_CMAKE_CONFIGS="$AUTOBUILD_TMP_DIR/deptrace-cmake-configs.txt"
  if ! "$AUTOBUILD_ROOT/deptrace-init"; then
    log "disabling deptrace as we were not able to initialize the deptrace server"
    export CODEQL_EXTRACTOR_CPP_AUTOINSTALL_DEPENDENCIES=false
  fi
fi

if [[ "${CODEQL_EXTRACTOR_CPP_BUILD_MODE:-}" == "none" ]]; then
  "$AUTOBUILD_ROOT/$CODEQL_PLATFORM/bmn"
  "$AUTOBUILD_ROOT/diagnostics/emit.sh" build-mode-none
  exit 0
fi

source "$AUTOBUILD_ROOT/lib/wrapping.sh"
install_cc_wrappers

export AUTOBUILD_PHASE=prebuild
"$AUTOBUILD_ROOT/do-prebuild"

export AUTOBUILD_PHASE=build
"$AUTOBUILD_ROOT/do-build"
