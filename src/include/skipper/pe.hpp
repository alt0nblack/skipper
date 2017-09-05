#pragma once

#include <windows.h>

#include <stdint.h>

#include <skipper/error.hpp>

#define RVA_TO_VA(dos, rva) ((ULONG_PTR)(dos) + (rva))
typedef DWORD (WINAPI *LPMIGRATION_ROUTINE)(void);

typedef struct __MIGRATION
{
   LPVOID memoryBase;
   SIZE_T memorySize;
   LPMIGRATION_ROUTINE entryPoint;
} MIGRATION, *LPMIGRATION;

PIMAGE_DOS_HEADER PEGetDOSHeader(LPVOID);
PIMAGE_NT_HEADERS PEGetNTHeaders(PIMAGE_DOS_HEADER);
DWORD PEDoubleRefImports(PIMAGE_DOS_HEADER);
DWORD PERelocateImage(LPVOID, uint64_t);
DWORD WINAPI PEMigrateFromDLLThread(LPVOID);
DWORD PEMigrateFromDLL(HINSTANCE, LPMIGRATION_ROUTINE);

