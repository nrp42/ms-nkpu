
#include <cstddef>
#include <log/message_types.h>
#include <log/message_initializer.h>

extern const isc::log::MessageID MSNKPU_LOAD_ERROR = "MSNKPU_LOAD_ERROR";
extern const isc::log::MessageID MSNKPU_REQUEST = "MSNKPU_REQUEST";
extern const isc::log::MessageID MSNKPU_PROCESS_REQUEST = "MSNKPU_PROCESS_REQUEST";
extern const isc::log::MessageID MSNKPU_PROCESS_NOPKEY = "MSNKPU_PROCESS_NOPKEY";
extern const isc::log::MessageID MSNKPU_PROCESS_ERROR = "MSNKPU_PROCESS_ERROR";
extern const isc::log::MessageID MSNKPU_UNLOAD = "MSNKPU_UNLOAD";

namespace {

const char* values[] = {
    "MSNKPU_LOAD_ERROR", "loading MS NKPU hooks library failed: %1",
    "MSNKPU_REQUEST", "recognized a BITLOCKER unlock query: %1",
    "MSNKPU_PROCESS_REQUEST", "Valid unlock request received: %1",
    "MSNKPU_PROCESS_NOPKEY", "No private key for thumbprint '%1' found",
    "MSNKPU_PROCESS_ERROR", "An error occurred processing query %1: %2",
    "MSNKPU_UNLOAD", "MS NKPU hooks library has been unloaded",
    NULL
};

const isc::log::MessageInitializer initializer(values);

} // Anonymous namespace

