#!/bin/bash -e

BUILD="$1"
LOG="$2"

SED_PROGRAM=""

COMMAND_NOT_FOUND="([Nn]o such file or directory|([Cc]ommand )?[Nn]ot found)"

function map() {
  local regex="$1"
  local diagnostic="$2"
  shift 2
  SED_PROGRAM+="
    s#.*$regex.*#$diagnostic $BUILD $@#p;
  "
}

map "(apt(-get|itude)?): $COMMAND_NOT_FOUND" expected-ubuntu '\1'

if [[ "$(uname)" != Darwin ]]; then
  map "xcodebuild: $COMMAND_NOT_FOUND" expected-macos xcodebuild
fi

function emit() {
  "$(dirname "$0")/emit.sh" "$@"
}

sed -Ene "$SED_PROGRAM" "$LOG" | sort -u | while read diagnostic; do
  emit $diagnostic
done
