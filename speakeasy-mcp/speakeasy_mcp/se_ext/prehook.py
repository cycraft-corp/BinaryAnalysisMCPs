from .hooks import prehook

from speakeasy.winenv.defs.nt import ddk
from speakeasy.windows.winemu import WindowsEmulator
import struct
from typing import Callable

@prehook("ntdll")
def NtQuerySystemInformation(emu:WindowsEmulator, ori_func:Callable, sysclass:int, sysinfo:int, syslen:int, retlen:int):
    """
    NTSTATUS WINAPI NtQuerySystemInformation(
        _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _Inout_   PVOID                    SystemInformation,
        _In_      ULONG                    SystemInformationLength,
        _Out_opt_ PULONG                   ReturnLength
        );
    """
    
    match sysclass:
        case ddk.SYSTEM_INFORMATION_CLASS.SystemBasicInformation:
            # Sample values for a system with 1 processor
            values = {
                "Reserved": 0x11111111,
                "TimerResolution": 0x22222222,
                "PageSize": 0x1000,
                "NumberOfPhysicalPages": 0x33333333,
                "LowestPhysicalPageNumber": 0x00000001,
                "HighestPhysicalPageNumber": 0x0000FFFF,
                "AllocationGranularity": 0x10000,
                "MinimumUserModeAddress": 0x10000,
                "MaximumUserModeAddress": 0x7FFF0000,
                "ActiveProcessorsAffinityMask": 0x01,  # Only CPU 0
                "NumberOfProcessors": 0x01,            # 1 processor
            }
            match emu.get_arch_name():
                case "amd64":
                    # --- 64-bit layout ---
                    # 7 * ULONG (4 bytes)
                    # 2 * ULONG_PTR (8 bytes)
                    # 1 * KAFFINITY (ULONG_PTR = 8 bytes)
                    # 1 * CHAR (1 byte)
                    packed_64 = struct.pack(
                        "<7I3Q B",  # Little-endian: 7 ULONGs, 3 QWORDs, 1 CHAR
                        values["Reserved"],
                        values["TimerResolution"],
                        values["PageSize"],
                        values["NumberOfPhysicalPages"],
                        values["LowestPhysicalPageNumber"],
                        values["HighestPhysicalPageNumber"],
                        values["AllocationGranularity"],
                        values["MinimumUserModeAddress"],
                        values["MaximumUserModeAddress"],
                        values["ActiveProcessorsAffinityMask"],
                        values["NumberOfProcessors"]
                    )

                    # Pad to match 0x39 (last offset 0x38 + 1 CHAR + alignment padding)
                    packed_64 += b"\x00" * (0x40 - len(packed_64))  # Optional alignment to 64 bytes
                    
                    emu.mem_write(sysinfo, packed_64)

                case "x86":
                    # --- 32-bit layout ---
                    # 7 * ULONG (4 bytes)
                    # 2 * ULONG_PTR (4 bytes)
                    # 1 * KAFFINITY (ULONG_PTR = 4 bytes)
                    # 1 * CHAR (1 byte)
                    packed_32 = struct.pack(
                        "<7I3I B",  # Little-endian: 7 ULONGs, 3 ULONG_PTRs, 1 CHAR
                        values["Reserved"],
                        values["TimerResolution"],
                        values["PageSize"],
                        values["NumberOfPhysicalPages"],
                        values["LowestPhysicalPageNumber"],
                        values["HighestPhysicalPageNumber"],
                        values["AllocationGranularity"],
                        values["MinimumUserModeAddress"],
                        values["MaximumUserModeAddress"],
                        values["ActiveProcessorsAffinityMask"],
                        values["NumberOfProcessors"]
                    )

                    # Pad to match 0x2C (last offset 0x28 + 1 CHAR + alignment padding)
                    packed_32 += b"\x00" * (0x2C - len(packed_32))
                    
                    emu.mem_write(sysinfo, packed_32)
                    
                case _:
                    raise ValueError(f"does not support arch {emu.get_arch_name()}")
        case _:
            return ori_func([sysclass, sysinfo, syslen, retlen])


    return ddk.STATUS_SUCCESS

