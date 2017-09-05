#include "main.hpp"

int
main
(int argc, char *argv[])
{
#ifdef SKIPPER_INJECT
   /* this isn't technically a C++ example, so I'll just be doing a good ol' cast */
   CreateThread(NULL, NULL, (DWORD (WINAPI *)(LPVOID))LoadLibrary, L"skipper.dll", NULL, NULL);
#else
   LoadLibrary(L"skipper.dll");
#endif
   
   for (;;)
      Sleep(1000);

   return 0;
}
