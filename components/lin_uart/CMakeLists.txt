idf_component_register(
    SRCS "lin_uart.c"
    INCLUDE_DIRS "include"
    REQUIRES
        driver
        esp_timer
        freertos
        esp_rom
)