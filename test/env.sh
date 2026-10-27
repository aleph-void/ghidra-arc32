# Sourced by the test scripts. Ghidra's headless script runner takes a user-wide OSGi lock in its
# settings directory; a private settings directory keeps parallel runs (and other Ghidra jobs of
# the same user) from serialising on it.
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
if [[ ${JAVA_TOOL_OPTIONS:-} != *application.settingsdir* ]]; then
	export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }-Dapplication.settingsdir=${ARC_GHIDRA_SETTINGS:-${TMPDIR:-/tmp}/arc32-ghidra-settings}"
fi
