AUTOBUILD_TRIED_STEPS="$AUTOBUILD_TMP_DIR/tried_steps.txt"
AUTOBUILD_TRIED_STEPS_DATA="$AUTOBUILD_TMP_DIR/tried_steps.jsonl"

function join_lines() {
  sed -e:x -e'$!N; s/\n/'"$1"'/; tx'
}

function move_directory_to_tmp() {
  local name="$1"
  local kind="$2"
  local source="$3"
  local target="$AUTOBUILD_TMP_DIR/$name/$kind"
  [[ -d "$source" ]] || return 0
  rm -rf "$target"
  mv "$source" "$target"
  mkdir "$source"
}

function merge_directory_from_tmp() {
  local name="$1"
  local kind="$2"
  local source="$AUTOBUILD_TMP_DIR/$name/$kind"
  local target="$3"
  [[ -d "$source" ]] || return 0
  mkdir -p "$target"
  (
    cd "$source"
    find . -not -type d | while read file; do
      mkdir -p "$(dirname "$target/$file")"
      mv "$file" "$target/$file"
    done
  )
}

function move_directories_to_tmp() {
  local name="$1"
  mkdir -p "$AUTOBUILD_TMP_DIR/$name"
  move_directory_to_tmp "$name" trap "$CODEQL_EXTRACTOR_CPP_TRAP_DIR"
  move_directory_to_tmp "$name" log "$CODEQL_EXTRACTOR_CPP_LOG_DIR"
  move_directory_to_tmp "$name" src "$CODEQL_EXTRACTOR_CPP_SOURCE_ARCHIVE_DIR"
  move_directory_to_tmp "$name" scratch "$CODEQL_EXTRACTOR_CPP_SCRATCH_DIR"
}

function merge_directories_from_tmp() {
  local name="$1"
  merge_directory_from_tmp "$name" trap "$CODEQL_EXTRACTOR_CPP_TRAP_DIR"
  merge_directory_from_tmp "$name" log "$CODEQL_EXTRACTOR_CPP_LOG_DIR"
  merge_directory_from_tmp "$name" src "$CODEQL_EXTRACTOR_CPP_SOURCE_ARCHIVE_DIR"
  merge_directory_from_tmp "$name" scratch "$CODEQL_EXTRACTOR_CPP_SCRATCH_DIR"
}

function get_failed_command_output_file() {
  local name="$1"
  echo "$AUTOBUILD_TMP_DIR/$name/scratch/autobuild.out"
}

function deptrace_summary() {
  local list_file="$AUTOBUILD_TMP_DIR/deptrace.list"
  installed="[$(sed -n '/^[^!]/{s/^\|$/"/g;p}' "$list_file" | join_lines ,)]"
  failed="[$(sed -n '/^!/{s/^!\|$/"/g;p}' "$list_file" | join_lines ,)]"
  "$AUTOBUILD_ROOT/diagnostics/emit.sh" deptrace --installedPackages "$installed" --failedPackages "$failed"
  if [[ -s "$list_file" ]]; then
    log "auto installed the following packages:"
    while read -r pkg; do
      if [[ "$pkg" = !* ]]; then
        log "  ${pkg:1} (installation failed!)"
      else
        log "  $pkg"
      fi
    done < "$list_file"
  fi
}

function count_occurrences() {
  local needle="$1"
  local file="$2"
  if [[ -f "$file" ]]; then
    grep -o "$needle" "$file" | wc -l
  else
    echo 0
  fi
}

function dump_build_trial_telemetry_info() {
  local label="$1"
  local cmd="$2"
  local exit_status="$3"
  local extractor_status_file="$CODEQL_EXTRACTOR_CPP_SCRATCH_DIR/extraction_status"
  local extractor_failures="$(count_occurrences f "$extractor_status_file")"
  local extractor_successes="$(count_occurrences s "$extractor_status_file")"
  printf '{ "label": "%s", "command": "%s", "exit_status": %d, "extractor-failures": %d, "extractor-successes": %d }\n' \
    "$label" "$cmd" "$exit_status" "$extractor_failures" "$extractor_successes" \
    >> "$AUTOBUILD_TRIED_STEPS_DATA"
}

function autobuild_summary() {
  local exit_status="$1"
  local tried="[]"
  if [[ -s "$AUTOBUILD_TRIED_STEPS_DATA" ]]; then
    tried="[$(cat "$AUTOBUILD_TRIED_STEPS_DATA" | join_lines ,)]"
  fi
  local severity=$([[ "$exit_status" == 0 ]] && echo note || echo error)
  SEVERITY=$severity "$AUTOBUILD_ROOT/diagnostics/emit.sh" summary --tried "$tried"
}

function cleanup() {
  local exit_status="$?"
  [[ -d "$AUTOBUILD_TMP_DIR" ]] || return 0
  if [[ -s "$AUTOBUILD_TMP_DIR/deptrace.pid" ]]; then
    kill "$(cat "$AUTOBUILD_TMP_DIR/deptrace.pid")"
    deptrace_summary
    mv "$AUTOBUILD_TMP_DIR/deptrace.list" "$CODEQL_EXTRACTOR_CPP_LOG_DIR/"
  fi
  autobuild_summary $exit_status
  if [[ -s "$AUTOBUILD_TRIED_STEPS" && "$exit_status" != 0 ]]; then
    # merge all artifacts from failed trials into the normal target directories
    cat "$AUTOBUILD_TRIED_STEPS" | while read build; do
      merge_directories_from_tmp "$build"
    done
  fi
  mv "$AUTOBUILD_TMP_DIR" "$CODEQL_EXTRACTOR_CPP_SCRATCH_DIR/autobuild_failed_trials" || true
  exit "$exit_status"
}
