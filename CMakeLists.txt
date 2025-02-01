# CMakeLists.txt
#
# Polychat Dissector
# By Stephen Ludin <sludin@ludin.org>
# Copyright 2025 Stephen Ludin
#
# SPDX-License-Identifier: MIT
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(polychat 0 0 4 0)

set(DISSECTOR_SRC
	packet-polychat.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_wireshark_plugin_library(polychat epan)

target_link_libraries(polychat epan)

install_plugin(polychat epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  polychat
	SWITCHES
	  --group dissectors-prohibited
	  --group dissectors-restricted
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)
