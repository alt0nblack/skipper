#pragma once

#include <windows.h>
#include <ctime>

#include <skipper/error.hpp>
#include <skipper/pe.hpp>

int CALLBACK WinMain(HINSTANCE, HINSTANCE, LPSTR, int);
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID);
VOID WINAPI ServiceMain(DWORD, LPWSTR *);
DWORD WINAPI MigrationMain(void);
