#!/bin/bash

set -eu
set -o pipefail

wrapped="%WRAPPED%"
name="$(basename "$wrapped")"

if [[ "${AUTOBUILD_PHASE:-}" = prebuild ]]; then
  # during configuration it is better to keep all warning flags in, as those flags might be
  # required to correctly detect compiler or library features
  exec "$wrapped" "$@"
fi

transformed_args=()
# ignore all warning options, as they are too coupled with the toolchain, including the warning names
# warning options are `-W*` except for `-W{a,l,p},*` which are assembler, linker and preprocessor options
for arg in "$@"; do
  [[ "$arg" =~ ^-W.[^,] || "$arg" = --pedantic-errors ]] && continue
  transformed_args+=("$arg")
done

# on macOS gcc & co can actually be clang in disguise. To detect which is which, run `--version`
if [[ "$name" =~ clang || "$("$wrapped" --version)" =~ clang ]]; then
  # Some warnings are errors by default in clang, and the exact set depends on version. Instead of
  # figuring out the right combination of -Wno-error=... flags, silence all warnings.
  transformed_args+=(-Wno-everything)
else
  # very rough heuristic to detect C++ compilation to add -fpermissive
  args=" ${transformed_args[*]} "
  comp_mode_pattern="\s-x"
  cpp_mode_pattern="\s-x\s*c\+\+\s"
  cpp_source_pattern="\.(cc|cp|cxx|cpp|CPP|c\+\+|C)\s"
  if [[ $args =~ $cpp_mode_pattern || ( ! $args =~ $comp_mode_pattern && $args =~ $cpp_source_pattern ) ]]; then
    transformed_args+=(-fpermissive)
  fi
fi

exec "$wrapped" "${transformed_args[@]}"
