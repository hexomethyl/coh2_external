#include <iostream>
#include <Windows.h>
#include <psapi.h>
bool patch_bytes (HANDLE process, uint64_t address, uint8_t* buffer, SIZE_T length) {

    DWORD old_protection;

    VirtualProtectEx((void*)process, (void*)address, length, PAGE_EXECUTE_READWRITE, &old_protection);

    SIZE_T bytes_written;
    bool success = WriteProcessMemory((void*)process, (void*)address, buffer, length, &bytes_written);

    VirtualProtectEx((void*)process, (void*)address, length, old_protection, &old_protection);
    return success;
}

HMODULE get_module(HANDLE process)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    std::string mod_name = "RelicCoH2.exe";

    if (EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded))
    {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            std::string mod_name;
            mod_name.resize(256);
            if (GetModuleFileNameExA(process, hMods[i], mod_name.data(), mod_name.size()))
            {
                if (mod_name.find(mod_name) != std::string::npos)
                    return hMods[i];
            }
        }
    }
    return nullptr;
}


int main()
{
    /*
     Disable fog info
     RelicCoH2.exe + 0xF22796
     0x32 0xC0 -> 0xB0 0x01
     48 83 EC 28 80 B9 ? ? ? ? ? 74 29 E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 84 C0 75 11 E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 84 C0 74 07
    */

    /*
     Show squad status
     RelicCoH2.exe + 0xF240C7
     0x74 0x1E -> 0xEB 0x1E
     48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 80 B9 ? ? ? ? ? 41 0F B6 F9 49 8B F0 48 8B DA 74 22 E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 84 C0 75 34 E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 84 C0 75 23
     */

    /*
     Debug mode
     [RelicCoH2.exe + 0x2D0B9E0] + 0x4E0
     Write 0x1
     48 8B C4 48 89 48 08 53 55 56 57 41 56 41 57 48 81 EC ? ? ? ? 0F 29 70 B8 48 8B F9 45 33 FF 41 8B EF 44 89 78 10 48 8D 05 ? ? ? ? 48 89 01 48 83 C1 08 E8 ? ? ? ? 90 48 8D 4F 18 E8 ? ? ? ? 90 44 88 BF ? ? ? ? 48 8D B7 ? ? ? ? 48 89 B4 24 ? ? ? ? 48 8D 5E 08 C7 03 ? ? ? ? 48 C7 83 ? ? ? ? ? ? ? ?
     */

    /*
     Disable script blocking

     RelicCoH2.exe + 0x8434B4
     80 B8 E0 04 00 00 00 -> 80 B8 E0 04 00 00 01

     Sig1:
     48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC 20 48 8B DA 48 8B F9 F2 0F 10 15 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? F2 0F 10 15 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? F2 0F 10 15 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? F2 0F 10 15 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? F2 0F 10 15 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? 0F 57 D2 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? F2 0F 10 15 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? F2 0F 10 15 ?
     ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? F2 0F 10 15 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 48 8B F0 48 89 45 58 48 85 C0 74 34 4C 8D 05 ? ? ? ? 48 8B D3 48 8B C8 E8 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 06 48 8D 05 ? ? ? ? 48 89 46 28 48 8D 05 ? ? ? ? 48 89 46 20 EB 02

     RelicCoH2.exe + 0x82E95E
     80 B8 E0 04 00 00 00 -> 80 B8 E0 04 00 00 01

     Sig2:
     48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 E8 ? ? ? ? 48 8B D8 48 8D 3D ? ? ? ? 48 8D 35 ? ? ? ? 48 8B 17 48 8B CB E8 ? ? ? ? 48 83 C7 08 48 3B FE 75 EC E8 ? ? ? ? 80 B8 ? ? ? ? ? 0F 84 ? ? ? ?
     */

    /*
     Custom zoom limit

     RelicCoH2.exe + 0xBE0D6E

     F3 0F 10 99 ? ? ? ? 0F 2F CB
     */

    /*
     Custom veto limit

     RelicCoH2.exe + 0x5053C9

    0F 84 ? ? ? ? 48 8D 5F 08 48 83 7F ? ?
     */

    HWND window = FindWindowA(nullptr, "Company Of Heroes 2");
    DWORD pid;

    if(!GetWindowThreadProcessId(window, &pid))
        return 1;

    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if(!process_handle)
        return 1;

    uint64_t base_address = (uint64_t)get_module(process_handle);

    if(!base_address)
        return 1;

    if(patch_bytes(process_handle, base_address + 0xF22796, (uint8_t*)"\xB0\x01", 2))
        printf("FOW disabled\n");

    if(patch_bytes(process_handle, base_address + 0xF240C7, (uint8_t*)"\xEB\x1E", 2))
        printf("Squad status shown\n");


    uint8_t zoom_shellcode[] = {
                        0xC6, 0x83, 0x44, 0x05, 0x00, 0x00, 0x00,       //mov    BYTE PTR [rbx+0x544],0x0
                        0x49, 0xC7, 0xC3, 0xFF, 0x00, 0x00, 0x00,       //mov    r11, 0xFF
                        0xF3, 0x49, 0x0F, 0x2A, 0xC3,                   //cvtsi2ss xmm0,r11
                        0xF3, 0x0F, 0x11, 0x81, 0x94, 0x04, 0x00, 0x00, //movss  DWORD PTR [rcx+0x494],xmm0
                        0x48, 0x83, 0xC4, 0x20,                         //add    rsp,0x20
                        0x5B,                                           //pop    rbx
                        0xC3                                            //ret
    };
    
    uint64_t zoom_stub = (uint64_t)VirtualAllocEx(process_handle, nullptr, sizeof(zoom_shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if(patch_bytes(process_handle, zoom_stub, zoom_shellcode, sizeof(zoom_shellcode)))
        printf("Zoom shellcode written to page, %p\n", zoom_stub);

    BYTE jmpStub[] = {
            0x49, 0xBA, //movabs r10,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // x64 bit address
            0x41, 0xFF, 0xE2 // jmp r10
    };

    memcpy(jmpStub+2, (void*)&zoom_stub, sizeof(uint64_t));

    if(patch_bytes(process_handle, base_address + 0xBE0D6E, jmpStub, sizeof(jmpStub)))
        printf("Jump written in zoom function, %p\n", base_address + 0xBE0D6E);

    uint8_t veto_shellcode[] = { 0xB8, 0x32, 0x00, 0x00, 0x00,              //mov eax, 50
                                0x41, 0x89, 0x85, 0x30, 0x0D, 0x00, 0x00,   //mov [r13+0xD30], eax
                                0x49, 0x8B, 0x5B, 0x20,                     //mov rbx, [r11+0x20]
                                0x49, 0x8B, 0x73, 0x28,                     //mov rsi, [r11+0x28]
                                0x49, 0x8B, 0x7B, 0x30,                     //mov rdi, [r11+0x30]
                                0x4D, 0x8B, 0x6B, 0x38,                     //mov r13, [r11+0x38]
                                0x4C, 0x89, 0xDC,                           //mov rsp, r11
                                0x41, 0x5F,                                 //pop r15
                                0x41, 0x5E,                                 //pop r14
                                0x5D,                                       //pop rbp
                                0xC3                                        //ret
    };

    uint64_t veto_stub = (uint64_t)VirtualAllocEx(process_handle, nullptr, sizeof(veto_shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if(patch_bytes(process_handle, veto_stub, veto_shellcode, sizeof(veto_shellcode)))
        printf("Veto shellcode written to page, %p\n", veto_stub);

    memcpy(jmpStub+2, (void*)&veto_stub, sizeof(uint64_t));

    if(patch_bytes(process_handle, base_address + 0x5053C9, jmpStub, sizeof(jmpStub)))
        printf("Jump written in veto function, %p\n", base_address + 0x5053C9);

    /*
    uint64_t address = 0;
    SIZE_T bytes_read;
    ReadProcessMemory((void*)process_handle, (void*)(base_address + 0x2D0B9E0), &address, 8, &bytes_read);
    if(patch_bytes(process_handle, address + 0x4E0, (BYTE*)"\x01", 1))
        printf("Debug mode enabled\n");
    */
    getchar();
    return 0;
}
