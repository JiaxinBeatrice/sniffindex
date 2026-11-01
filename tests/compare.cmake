# Runs sniffindex on CAPTURE and compares the result with what tshark wrote for it.
# With PATH_NAME the capture is copied to that name first.
get_filename_component(name "${CAPTURE}" NAME)
file(MAKE_DIRECTORY "${WORK}")

set(input "${CAPTURE}")
if(DEFINED PATH_NAME)
    set(input "${WORK}/${PATH_NAME}")
    configure_file("${CAPTURE}" "${input}" COPYONLY)
endif()

set(output "${WORK}/${name}.tsv")
if(DEFINED PATH_NAME)
    set(output "${WORK}/${PATH_NAME}.tsv")
endif()
file(REMOVE "${output}")

execute_process(
    COMMAND "${SNIFFINDEX}" "${input}" -o "${output}"
    RESULT_VARIABLE result
    ERROR_VARIABLE errors
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "sniffindex failed with ${result}: ${errors}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E compare_files "${output}" "${CAPTURE}.tsv"
    RESULT_VARIABLE different
)
if(different)
    message(FATAL_ERROR "${output} differs from ${CAPTURE}.tsv")
endif()
