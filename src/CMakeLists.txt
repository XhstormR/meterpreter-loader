set(APP_NAME main)

aux_source_directory(. SOURCE)

list(APPEND SOURCE ./resources/resource.rc)

add_library(${APP_NAME} SHARED ${SOURCE})

target_link_libraries(${APP_NAME}
        PRIVATE ws2_32
)

install(TARGETS ${APP_NAME} RUNTIME)
install(PROGRAMS ${PROJECT_SOURCE_DIR}/assets/start.vbs TYPE BIN)
