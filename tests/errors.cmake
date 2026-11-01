# Input sniffindex can't read has to stop it with a message and without a result.
file(MAKE_DIRECTORY "${WORK}")

function(expect_failure name expected_message)
    set(output "${WORK}/bad_${name}.tsv")
    file(REMOVE "${output}")
    execute_process(
        COMMAND "${SNIFFINDEX}" "${SOURCE_FOLDER}/tests/data/bad/${name}" -o "${output}"
        RESULT_VARIABLE result
        ERROR_VARIABLE errors
    )
    if(result EQUAL 0)
        message(FATAL_ERROR "${name} was accepted")
    endif()
    if(NOT errors MATCHES "${expected_message}")
        message(FATAL_ERROR "${name}: expected '${expected_message}', got '${errors}'")
    endif()
    if(EXISTS "${output}")
        message(FATAL_ERROR "${name} left ${output} behind")
    endif()
endfunction()

expect_failure(gzip.pcap "compressed")
expect_failure(text.pcap "not a capture")
expect_failure(ethernet.pcap "link type 1")
