function install_cc_wrappers() {
  local dstdir="$CODEQL_EXTRACTOR_CPP_SCRATCH_DIR/autobuild/bin"
  # install a compiler wrapper for each common compiler found on `PATH`
  mkdir -p "$dstdir"
  for bin in cc c++ gcc g++ clang clang++ armclang armclang++; do
    local src="$(which $bin 2> /dev/null || true)"
    local dst="$dstdir/$bin"
    if [[ -n "$src" ]]; then
      sed "s=%WRAPPED%=$src=" "$AUTOBUILD_ROOT/wrappers/cc_wrapper_template.sh" > "$dst"
      chmod +x "$dst"
    fi
  done
  export PATH="$dstdir:$PATH"
}
