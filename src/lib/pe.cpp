#include <skipper/pe.hpp>

PIMAGE_DOS_HEADER
PEGetDOSHeader
(LPVOID buffer)
{
   PIMAGE_DOS_HEADER dosHeader;

   dosHeader = (PIMAGE_DOS_HEADER)buffer;

   if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
      return NULL;

   return dosHeader;
}

PIMAGE_NT_HEADERS
PEGetNTHeaders
(PIMAGE_DOS_HEADER dosHeader)
{
   LPBYTE byteHeader;
   PIMAGE_NT_HEADERS ntHeaders;

   byteHeader = (LPBYTE)dosHeader;
   byteHeader += dosHeader->e_lfanew;
   ntHeaders = (PIMAGE_NT_HEADERS)byteHeader;

   if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
      return NULL;

   return ntHeaders;
}

DWORD
PERelocateImage
(LPVOID peImage, uint64_t oldBase)
{
   uint64_t newBase;
   uint64_t delta;
   PIMAGE_DOS_HEADER dosHeaders;
   PIMAGE_NT_HEADERS ntHeaders;
   PIMAGE_BASE_RELOCATION relocationHeader;

   DR_DEBUG(L"[+] Attempting to relocate image 0x%I64X to 0x%I64X", (ULONG_PTR)peImage, oldBase);

   newBase = (uint64_t)peImage;

   /* while this might overflow, that's okay-- we'll actually still land exactly
      where we want to go! */
   delta = newBase - oldBase;
   
   dosHeaders = PEGetDOSHeader(peImage);

   if (dosHeaders == NULL)
      DR_RETURN_ERROR(DR_ERROR_BAD_DOS_IMAGE, L"bad DOS image provided");

   ntHeaders = PEGetNTHeaders(dosHeaders);

   if (ntHeaders == NULL)
      DR_RETURN_ERROR(DR_ERROR_BAD_NT_IMAGE, L"bad NT image in DOS image");

   relocationHeader = (PIMAGE_BASE_RELOCATION)RVA_TO_VA(dosHeaders, ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

   if (relocationHeader == NULL)
      DR_RETURN_ERROR(DR_ERROR_BAD_RELOC_HEADER, L"bad relocation header");

   DR_DEBUG(L"[+] Found relocation directory at 0x%I64X", (ULONG_PTR)relocationHeader);
   
   while (relocationHeader->VirtualAddress)
   {
      DWORD blockSize = relocationHeader->SizeOfBlock;

      DR_DEBUG(L"[+] ... Parsing block 0x%I64X (size %d bytes)", (ULONG_PTR)relocationHeader, blockSize);
      
      if (blockSize >= sizeof(IMAGE_BASE_RELOCATION))
      {
         ULONG count = (blockSize - sizeof(IMAGE_BASE_RELOCATION))/sizeof(USHORT);
         PUSHORT typeOffset = (PUSHORT)(relocationHeader+1);

         for (ULONG i=0; i<count; ++i)
         {
            if (typeOffset[i])
            {
               uint64_t *relocation = (uint64_t *)RVA_TO_VA(dosHeaders, relocationHeader->VirtualAddress + (typeOffset[i] & 0xFFF));
               *relocation += delta;
            }
         }
      }

      relocationHeader = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocationHeader+blockSize);
   }

   DR_RETURN_ERROR(DR_ERROR_SUCCESS
                   ,L"[!] Image at 0x%08I64X relocated to 0x%08I64X"
                   ,oldBase
                   ,newBase);
}

DWORD WINAPI
PEMigrateFromDLLThread
(LPVOID threadArg)
{
   LPMIGRATION migration = (LPMIGRATION)threadArg;
   DWORD result;

   result = migration->entryPoint();

   ZeroMemory(migration->memoryBase, migration->memorySize);
   VirtualFree(migration->memoryBase, migration->memorySize, MEM_RELEASE);

   ZeroMemory(migration, sizeof(MIGRATION));
   HeapFree(GetProcessHeap(), NULL, migration);

   return 0;
}

DWORD
PEDoubleRefImports
(PIMAGE_DOS_HEADER dosHeader)
{
   PIMAGE_NT_HEADERS ntHeaders;
   PIMAGE_OPTIONAL_HEADER optional;
   ULONG importRVA;
   PIMAGE_IMPORT_DESCRIPTOR importTable;

   DR_DEBUG(L"[+] Double-reffing the imports.");

   ntHeaders = PEGetNTHeaders(dosHeader);

   if (ntHeaders == NULL)
      DR_RETURN_ERROR(DR_ERROR_BAD_NT_IMAGE, L"bad NT image in DOS image");

   optional = &ntHeaders->OptionalHeader;
   importRVA = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

   /* no imports? no problem! you might be intentionally doing that. */
   if (importRVA == 0)
   {
      DR_DEBUG(L"[+] Hmm, no import table... well, nevermind I suppose!");
      return DR_ERROR_SUCCESS;
   }

   importTable = (PIMAGE_IMPORT_DESCRIPTOR)RVA_TO_VA(dosHeader, importRVA);
   DR_DEBUG(L"[+] Found import table at 0x%I64X", (ULONG_PTR)importTable);

   /* double up those refs! */
   while (importTable->OriginalFirstThunk != 0)
   {
      HMODULE loadCheck;
      char *name;

      if (importTable->Name == 0)
      {
         DR_DEBUG(L"[!] No name in import table. Malformed executables won't work here. Sorry!");
         DR_RETURN_ERROR(DR_ERROR_BAD_DLL_NAME, L"import name was NULL");
      }

      name = (char *)RVA_TO_VA(dosHeader, importTable->Name);

      DR_DEBUG("[+] ... Double-ref %S...", name);
      loadCheck = LoadLibraryA(name);

      if (loadCheck == NULL)
         DR_RETURN_ERROR(DR_ERROR_LOADLIBRARY_FAILURE, L"LoadLibrary failed");
      
      ++importTable;
   }

   DR_DEBUG(L"[!] Imports doubled-up.");

   return DR_ERROR_SUCCESS;
}

DWORD
PEMigrateFromDLL
(HINSTANCE dllHandle, LPMIGRATION_ROUTINE entryPoint)
{
   PIMAGE_DOS_HEADER dllDosHeader;
   PIMAGE_NT_HEADERS dllNTHeader;
   LPMIGRATION migration;
   uint64_t delta;
   LPTHREAD_START_ROUTINE threadStart;
   HANDLE threadHandle;
   DWORD result = DR_ERROR_GENERAL;

   DR_DEBUG(L"[+] Migrating handle 0x%I64X away from kernel DLL section.", (ULONG_PTR)dllHandle);
   
   dllDosHeader = PEGetDOSHeader((LPVOID)dllHandle);

   if (dllDosHeader == NULL)
      DR_RETURN_ERROR(DR_ERROR_BAD_DOS_IMAGE, L"bad DOS image provided");

   dllNTHeader = PEGetNTHeaders(dllDosHeader);

   if (dllNTHeader == NULL)
      DR_RETURN_ERROR(DR_ERROR_BAD_NT_IMAGE, L"bad NT image in DOS image");

   /* prior to migration, let's make sure to double-up on the references to the
      DLLs our DLL has already imported! */
   PEDoubleRefImports(dllDosHeader);

   migration = (LPMIGRATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MIGRATION));

   if (migration == NULL)
      DR_RETURN_ERROR(DR_ERROR_HEAP_FAILURE, L"HeapAlloc failed");
   
   migration->memorySize = dllNTHeader->OptionalHeader.SizeOfImage;
   migration->memoryBase = VirtualAlloc(NULL, migration->memorySize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

   if (migration->memoryBase == NULL)
   {
      result = DR_ERROR_ALLOCATE_PAGE;
      DR_GOTO_ERROR(error_allocate_page, L"VirtualAlloc failed");
   }

   DR_DEBUG(L"[+] Allocated new process memory region 0x%I64X with size %I64d", (ULONG_PTR)migration->memoryBase, migration->memorySize);

   ZeroMemory(migration->memoryBase, migration->memorySize);
   CopyMemory(migration->memoryBase, (LPVOID)dllHandle, migration->memorySize);
   
   if (!DR_SUCCESS(result, PERelocateImage(migration->memoryBase, (uint64_t)dllHandle)))
      DR_GOTO_ERROR(error_relocation, L"DLL relocation failed");

   delta = (uint64_t)migration->memoryBase - (uint64_t)dllHandle;
   migration->entryPoint = (LPMIGRATION_ROUTINE)((uint64_t)entryPoint + delta);
   threadStart = (LPTHREAD_START_ROUTINE)((uint64_t)PEMigrateFromDLLThread + delta);

   DR_DEBUG(L"[+] Migration assigned new entrypoint 0x%I64X", (ULONG_PTR)entryPoint);

   threadHandle = CreateThread(NULL, 8192, threadStart, migration, NULL, NULL);

   if (threadHandle == NULL)
   {
      result = DR_ERROR_THREAD_FAILURE;
      DR_GOTO_ERROR(error_thread_creation, L"CreateThread failed");
   }

   DR_DEBUG(L"[!] Migration succeeded.");

   result = DR_ERROR_SUCCESS;

error_allocate_page:
error_relocation:
error_thread_creation:
   if (result != DR_ERROR_SUCCESS)
   {
      if (migration->memoryBase != NULL)
      {
         ZeroMemory(migration->memoryBase, migration->memorySize);
         VirtualFree(migration->memoryBase, migration->memorySize, MEM_RELEASE);
      }
      
      ZeroMemory(migration, sizeof(MIGRATION));
      HeapFree(GetProcessHeap(), NULL, migration);
   }

   return result;
}
