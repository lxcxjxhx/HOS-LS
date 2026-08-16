. "$AUTOBUILD_ROOT/lib/log.sh"
. "$AUTOBUILD_ROOT/lib/dirs.sh"
. "$AUTOBUILD_ROOT/lib/wrapping.sh"

function diagnose() {
  "$CODEQL_EXTRACTOR_CPP_ROOT/tools/diagnostics/diagnose-build.sh" "$@"
}

# by default, use first arg as name (the command without any of its arguments)
# with --name, override that
# with --name-from-full-cmd, use the whole command line
function try_running() {
  local name
  if [[ "$1" == --name ]]; then
    shift
    name="$1"
    shift
  elif [[ "$1" == --name-from-full-cmd ]]; then
    shift
    name="$*"
  else
    name=$1
  fi
  local out="$CODEQL_EXTRACTOR_CPP_SCRATCH_DIR/autobuild.out"
  log "trying to run $* [current dir: $PWD]"
  echo "$name" >> "$AUTOBUILD_TRIED_STEPS"
  "$@" 2>&1 | tee "$out"
  local status=${PIPESTATUS[0]}
  dump_build_trial_telemetry_info "$name" "$*" "$status"
  [[ "$status" == 0 ]] && return 0
  diagnose "$name" "$out"
  move_directories_to_tmp "$name"
  # reinstall wrappers that got moved away
  install_cc_wrappers
  return $status
}

function emit_diagnostics() {
  "$AUTOBUILD_ROOT/diagnostics/emit.sh" "$@"
}

function tried_everything() {
  if [[ -s "$AUTOBUILD_TRIED_STEPS" ]]; then
    emit_diagnostics build-command-failed '`'"$(uniq "$AUTOBUILD_TRIED_STEPS" | join_lines '`, `')"'`'
  else
    emit_diagnostics no-build-command
  fi
  exit 1
}
