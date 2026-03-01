cmake_minimum_required(VERSION 3.16)

# Include local components directory
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32_lin_sniffer)

# ── Auto-generate merged flash image after each build ──────────────
idf_build_get_property(python PYTHON)
idf_build_get_property(idf_path IDF_PATH)

add_custom_target(flash_image ALL
    DEPENDS app
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_SOURCE_DIR}/flash"
    COMMAND ${python} "${idf_path}/components/esptool_py/esptool/esptool.py"
            --chip esp32c6 merge_bin
            -o "${CMAKE_CURRENT_SOURCE_DIR}/flash/esp32c6_esp32_lin_sniffer_merged.bin"
            0x0000 "${CMAKE_BINARY_DIR}/bootloader/bootloader.bin"
            0x8000 "${CMAKE_BINARY_DIR}/partition_table/partition-table.bin"
            0xd000 "${CMAKE_BINARY_DIR}/ota_data_initial.bin"
            0x10000 "${CMAKE_BINARY_DIR}/esp32_lin_sniffer.bin"
    COMMENT "Merging flash image -> flash/esp32c6_esp32_lin_sniffer_merged.bin"
    VERBATIM
)