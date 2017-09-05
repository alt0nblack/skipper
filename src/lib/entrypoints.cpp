#include <skipper/entrypoints.hpp>

#ifndef HIDE_SKIPPER
DWORD WINAPI
MigrationMainThread
(LPVOID args)
{
   MigrationMain();
   return 0;
}

void
SpawnMigrationMainThread
(void)
{
   CreateThread(NULL, NULL, MigrationMainThread, NULL, NULL, NULL);
}
#endif

BOOL WINAPI
DllMain
(HINSTANCE dllInstance, DWORD fdwReason, LPVOID lpvReserved)
{
   DR_DEBUG(L"[+] DllMain called");
   DR_DEBUG(L"[+] ... dllInstance = 0x%I64X", (ULONG_PTR)dllInstance);
   DR_DEBUG(L"[+] ... fdwReason = %d (%s)", fdwReason,
            (fdwReason == DLL_PROCESS_ATTACH) ? L"DLL_PROCESS_ATTACH" :
            (fdwReason == DLL_PROCESS_DETACH) ? L"DLL_PROCESS_DETACH" :
            (fdwReason == DLL_THREAD_ATTACH) ? L"DLL_THREAD_ATTACH" :
            (fdwReason == DLL_THREAD_DETACH) ? L"DLL_THREAD_DETACH" :
            L"UNKNOWN_REASON");
   DR_DEBUG(L"[+] ... lpvReserved = 0x%I64X", (ULONG_PTR)lpvReserved);

   if (fdwReason == DLL_PROCESS_ATTACH)
   {
#ifdef HIDE_SKIPPER
      PEMigrateFromDLL(dllInstance, MigrationMain);
      DR_DEBUG(L"[!] Lying to the loader. We failed. Sorry.");
      return FALSE;
#else
      SpawnMigrationMainThread();
#endif
   }

   return TRUE;
}

DWORD WINAPI
MigrationMain
(void)
{
   for (;;)
   {
      std::time_t timeObj = std::time(nullptr);
      DR_DEBUG(L"[+] Skipper alive as of %S", std::asctime(std::gmtime(&timeObj)));
      Sleep(3000);
   }
   
   return DR_ERROR_SUCCESS;
}
