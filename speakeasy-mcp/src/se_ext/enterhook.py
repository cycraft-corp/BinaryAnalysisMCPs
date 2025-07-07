from .hooks import enterhook

from speakeasy.windows.winemu import WindowsEmulator
from speakeasy.winenv.defs.nt.ntoskrnl import CLIENT_ID
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.windows.regman import RegKey

@enterhook("ntdll")
def NtOpenProcess(emu:WindowsEmulator, process_handle, desired_access, object_attr, pcid):
    '''
    __kernel_entry NTSYSCALLAPI NTSTATUS NtOpenProcess(
        [out]          PHANDLE            ProcessHandle,
        [in]           ACCESS_MASK        DesiredAccess,
        [in]           POBJECT_ATTRIBUTES ObjectAttributes,
        [in, optional] PCLIENT_ID         ClientId
    );
    '''
    ptr_sz = emu.arch // 8

    pid = CLIENT_ID(ptr_sz).cast(
        emu.mem_read(pcid, CLIENT_ID(ptr_sz).sizeof())
    ).UniqueProcess
    hnd = 0
    proc = emu.get_object_from_id(pid)
    if proc:
        hnd = emu.get_object_handle(proc)
    else:
        emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
    emu.mem_write(process_handle, hnd.to_bytes(ptr_sz, 'little'))


@enterhook("ntdll")
def RtlAdjustPrivilege(emu:WindowsEmulator, privlege, enable, current_thread, enabled):
    '''
    NTSTATUS RtlAdjustPrivilege
    (
        ULONG    Privilege,
        BOOLEAN Enable,
        BOOLEAN CurrentThread,
        PBOOLEAN Enabled
    )
    '''
    pass

@enterhook("ntdll")
def NtFreeVirtualMemory(emu:WindowsEmulator, process_handle, base_address, region_size, free_type):
    '''
    __kernel_entry NTSYSCALLAPI NTSTATUS NtFreeVirtualMemory(
        [in]      HANDLE  ProcessHandle,
        [in, out] PVOID   *BaseAddress,
        [in, out] PSIZE_T RegionSize,
        [in]      ULONG   FreeType
    );
    '''
    # i'm 2 lazy to implement it :P
    pass

@enterhook("ntdll")
def NtOpenProcessToken(emu:WindowsEmulator, hProcess, DesiredAccess, pTokenHandle):
    '''
    __kernel_entry NTSYSCALLAPI NTSTATUS NtOpenProcessToken(
    [in]  HANDLE      ProcessHandle,
    [in]  ACCESS_MASK DesiredAccess,
    [out] PHANDLE     TokenHandle
    );
    '''
    # copy from https://github.com/mandiant/speakeasy/blob/22ef6f7bf5323b2b3ddb10f3c9b6bc150ac78c95/speakeasy/winenv/api/usermode/advapi32.py#L349
    rv = 0

    def get_max_int():
        return int.from_bytes(b'\xFF' * emu.get_ptr_size(), 'little')

    if hProcess == get_max_int():
        obj = emu.get_current_process()
    else:
        obj = emu.get_object_from_handle(hProcess)

    if obj:
        token = obj.get_token()
        hToken = token.get_handle()

        if pTokenHandle:
            hnd = (hToken).to_bytes(emu.get_ptr_size(), 'little')
            emu.mem_write(pTokenHandle, hnd)
            rv = 1
            emu.set_last_error(windefs.ERROR_SUCCESS)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

    return rv


@enterhook("bcrypt")
def BCryptGenRandom(emu:WindowsEmulator, hAlgorithm, pbBuffer, cbBuffer, dwFlags):
    '''
    NTSTATUS BCryptGenRandom(
    [in, out] BCRYPT_ALG_HANDLE hAlgorithm,
    [in, out] PUCHAR            pbBuffer,
    [in]      ULONG             cbBuffer,
    [in]      ULONG             dwFlags
    );
    '''
    emu.mem_write(pbBuffer, b"\x87" * cbBuffer)

@enterhook("advapi32")
def RegCreateKeyExW(emu:WindowsEmulator, hKey:int, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
    '''
    LSTATUS RegCreateKeyExW(
    [in]            HKEY                        hKey,
    [in]            LPCWSTR                     lpSubKey,
                    DWORD                       Reserved,
    [in, optional]  LPWSTR                      lpClass,
    [in]            DWORD                       dwOptions,
    [in]            REGSAM                      samDesired,
    [in, optional]  const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    [out]           PHKEY                       phkResult,
    [out, optional] LPDWORD                     lpdwDisposition
    );
    '''
    rv = windefs.ERROR_INVALID_HANDLE
    if hKey:
        key:RegKey = emu.reg_get_key(hKey)
        if not key:
            rv = windefs.ERROR_INVALID_HANDLE
        else:
            if lpSubKey:
                lpSubKey = emu.read_mem_string(lpSubKey)
                sub_key_path = key.get_path() + '\\' + lpSubKey
                emu.reg_create_key(sub_key_path)
            else:
                hKey = (hKey).to_bytes(emu.get_ptr_size(), 'little')
                emu.mem_write(phkResult, hKey)
                rv = windefs.ERROR_SUCCESS
    return rv


@enterhook("ntdll")
def NtCreateIoCompletion(emu:WindowsEmulator, IoCompletionHandle, DesiredAccess, ObjectAttributes, NumberOfConcurrentThreads):
    '''
    # ref: https://ntdoc.m417z.com/ntcreateiocompletion
    NTSYSCALLAPI
    NTSTATUS
    NTAPI
    NtCreateIoCompletion(
    _Out_ PHANDLE IoCompletionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ ULONG NumberOfConcurrentThreads
    );
    '''
    pass

@enterhook("ntdll")
def NtCreateMutant(emu:WindowsEmulator, MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner):
    '''
    NTAPI
    NtCreateMutant(
        _Out_ PHANDLE MutantHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
        _In_ BOOLEAN InitialOwner
        );
    '''
    pass
@enterhook("advapi32")
def RegCreateKeyExA(emu:WindowsEmulator, hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
    '''
    LSTATUS RegCreateKeyExA(
    [in]            HKEY                        hKey,
    [in]            LPCSTR                      lpSubKey,
                    DWORD                       Reserved,
    [in, optional]  LPSTR                       lpClass,
    [in]            DWORD                       dwOptions,
    [in]            REGSAM                      samDesired,
    [in, optional]  const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    [out]           PHKEY                       phkResult,
    [out, optional] LPDWORD                     lpdwDisposition
    );
    '''
    rv = windefs.ERROR_INVALID_HANDLE
    if hKey:
        key:RegKey = emu.reg_get_key(hKey)
        if not key:
            rv = windefs.ERROR_INVALID_HANDLE
        else:
            if lpSubKey:
                lpSubKey = emu.read_mem_string(lpSubKey)
                sub_key_path = key.get_path() + '\\' + lpSubKey
                emu.reg_create_key(sub_key_path)
            else:
                hKey = (hKey).to_bytes(emu.get_ptr_size(), 'little')
                emu.mem_write(phkResult, hKey)
                rv = windefs.ERROR_SUCCESS
    return rv

@enterhook("ntdll")
def RtlEnterCriticalSection(emu:WindowsEmulator, lpCriticalSection):
    '''
    # ref: https://ntdoc.m417z.com/rtlentercriticalsection
    NTSTATUS
    NTAPI
    RtlEnterCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    );

    '''
    pass


@enterhook("ntdll")
def RtlInitializeCriticalSection(emu:WindowsEmulator, CriticalSection):
    '''
    NTSTATUS
    NTAPI
    RtlInitializeCriticalSection(
        _Out_ PRTL_CRITICAL_SECTION CriticalSection
        );
    '''
    pass

@enterhook("ntdll")
def RtlLeaveCriticalSection(emu:WindowsEmulator, CriticalSection):
    '''
    #ref: https://ntdoc.m417z.com/rtlleavecriticalsection
    NTSTATUS
    NTAPI
    RtlLeaveCriticalSection(
        _Inout_ PRTL_CRITICAL_SECTION CriticalSection
        );
    '''
    pass