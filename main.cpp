#include <windows.h>
#include <iostream>
#include <vector>
#include "ntdll.h"
#include "DbgHelp.h"
#pragma comment(lib, "dbghelp.lib")

// Get DLL list
// Check code outside dll

// Structure to hold information about memory regions
struct MEMORY_REGION {
    LPVOID BaseAddress;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
};
struct MODULE_TEXT_SECTION {
    LPVOID BaseAddress;
    SIZE_T RegionSize;
};

PEB* GetPebInternal() {

#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif
    return peb;
}

std::wstring GetCurrentProcName() {
    wchar_t buffer[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, buffer, MAX_PATH);

    std::wstring procName(buffer);
    size_t pos = procName.find_last_of(L"\\/");

    return procName.substr(pos + 1);
}
MODULE_TEXT_SECTION GetModuleTextSection(HANDLE hModule) {

    MODULE_TEXT_SECTION moduleSection = { 0 };
    IMAGE_NT_HEADERS* ntHeaders = ImageNtHeader(hModule);

    if (!ntHeaders) {
        std::cerr << "Failed to get NT headers. Error: " << GetLastError() << std::endl;
        return moduleSection;
    }
    std::string textSectionName = ".text";
    IMAGE_SECTION_HEADER* sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
        strncpy_s(sectionName, (char*)sectionHeaders[i].Name, IMAGE_SIZEOF_SHORT_NAME);

        if (textSectionName == sectionName) {
            moduleSection.BaseAddress = (BYTE*)hModule + sectionHeaders[i].VirtualAddress;
            moduleSection.RegionSize = sectionHeaders[i].Misc.VirtualSize;
            return moduleSection;
        }
    }
    return moduleSection;
}

std::vector<MODULE_TEXT_SECTION> GetDllTextSections() {
    std::vector<MODULE_TEXT_SECTION> dllRegions;

    PEB* peb = GetPebInternal();

    LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY current = head;

    std::wstring procName = GetCurrentProcName();
    for (auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink) {
        LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (mod->BaseDllName.Buffer)
        {
            HMODULE hModule = GetModuleHandleW(mod->BaseDllName.Buffer);
            dllRegions.push_back(GetModuleTextSection(hModule));
        }
    }

    return dllRegions;
}
// Function to retrieve the current memory layout
std::vector<MEMORY_REGION> GetMemoryLayout() {
    std::vector<MEMORY_REGION> memoryRegions;

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = nullptr;

    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        MEMORY_REGION region;
        region.BaseAddress = mbi.BaseAddress;
        region.RegionSize = mbi.RegionSize;
        region.State = mbi.State;
        region.Protect = mbi.Protect;

        memoryRegions.push_back(region);
        address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize); // Move to the next region
    }
    return memoryRegions;
}
BOOL isOutsizeTextSection(MODULE_TEXT_SECTION textSection, MEMORY_REGION region) {
    if (region.BaseAddress < textSection.BaseAddress || region.BaseAddress >(BYTE*)textSection.BaseAddress + textSection.RegionSize) {
        return TRUE;
    }
    return FALSE;
}

VOID DetectMemoryModification() {

    std::vector<MEMORY_REGION> memoryLayouts = GetMemoryLayout();
    std::vector<MODULE_TEXT_SECTION> dllTextSections = GetDllTextSections();

    for (auto& memory : memoryLayouts) {
        for (auto dllTextSection : dllTextSections) {
            if (isOutsizeTextSection(dllTextSection, memory)) {
                std::cout << "Memory region outside of text section: " << memory.BaseAddress << std::endl;
            }
        }
    }
}

int main() {

    DetectMemoryModification();
    system("pause");

    return 0;
}
