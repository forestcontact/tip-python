
add_cython_target(_tip CXX)

add_library(_tip MODULE
    ${_tip}
)

python_extension_module(_tip)

target_link_libraries(_tip ${CMAKE_CURRENT_SOURCE_DIR}/tip/libtip.a)

if (APPLE)
    target_link_libraries(_tip "-framework Foundation")
endif(APPLE)

target_include_directories(_tip PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/tip
)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/tip/libtip.a
    COMMAND go build -o libtip.a -buildmode=c-archive
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tip/lib.go
    COMMENT "Creating libtip.a"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tip
)

add_custom_target(build_tip ALL
    COMMAND echo "Building libtip.a"
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tip/libtip.a
    # to make quotes printable,for example
    VERBATIM
)

install(TARGETS _tip LIBRARY DESTINATION pysrc)

