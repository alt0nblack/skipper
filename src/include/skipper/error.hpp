#pragma once

#include <skipper/debug.hpp>

#define DR_ERROR_SUCCESS 0x0
#define DR_ERROR_GENERAL 0x1
#define DR_ERROR_BAD_DOS_IMAGE 0x2
#define DR_ERROR_BAD_NT_IMAGE 0x3
#define DR_ERROR_BAD_RELOC_HEADER 0x4
#define DR_ERROR_ALLOCATE_PAGE 0x5
#define DR_ERROR_HEAP_FAILURE 0x6
#define DR_ERROR_THREAD_FAILURE 0x7
#define DR_ERROR_LOADLIBRARY_FAILURE 0x8
#define DR_ERROR_BAD_DLL_NAME 0x9

#define DR_SUCCESS(status, result) ((status = (result)) == DR_ERROR_SUCCESS)
#define DR_RETURN_ERROR(errorCode, message, ...) { DR_DEBUG(message, __VA_ARGS__); return errorCode; }
#define DR_GOTO_ERROR(errorLabel, message, ...) { DR_DEBUG(message, __VA_ARGS__); goto errorLabel; }
