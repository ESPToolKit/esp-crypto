# ESPCrypto exercises require ESP-IDF/Arduino runtime to access hardware
# accelerators for AES/SHA. Host builds only emit this notice so CI
# completes quickly; see test/test_esp_crypto for Unity-based device tests.
message(STATUS "ESPCrypto: tests are disabled for the host build.")
