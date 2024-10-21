using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Windows.Win32;
using Windows.Win32.Security;
using Windows.Win32.System.Memory;

namespace COST
{
    internal class ManagedUtils
    {
        const string lpszPrivilege = "SeLockMemoryPrivilege";
        private SafeFileHandle hToken;

        public IntPtr InitLargePages(uint array_size_bytes)
        {
            return _InitLargePages(array_size_bytes, false, false);
        }

        public IntPtr InitSmallPages(uint array_size_bytes)
        {
            return _InitSmallPages(array_size_bytes, false, false);
        }

        public void CleanLargePages(IntPtr x)
        {
            _CleanLargePages(x);
        }

        public void CleanSmallPages(IntPtr x)
        {
            _CleanSmallPages(x);
        }
        private unsafe IntPtr _InitLargePages(uint array_size_bytes, bool no_cache, bool write_combine)
        {
            if (!PInvoke.OpenProcessToken(PInvoke.GetCurrentProcess_SafeHandle(), TOKEN_ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES, out hToken))
            {
                Console.Write("OpenProcessToken() error {0}\n", Marshal.GetLastWin32Error());
                Environment.Exit(0);
            }

            // Call the user defined SetPrivilege() function to enable and set the needed privilege
            if (!SetPrivilege(hToken, lpszPrivilege, true))
            {
                Console.Write("SetPrivilege() error {0}\n", Marshal.GetLastWin32Error());
                Environment.Exit(0);
            }

            nuint largePageSize = PInvoke.GetLargePageMinimum();
            if (largePageSize == 0)
            {
                Console.Write("GetLargePageMinimum() error {0}\n", Marshal.GetLastWin32Error());
                //scanf_s("%*c");
                Environment.Exit(0);
            }

            nuint allocSize;
            if (array_size_bytes < largePageSize)
            {
                allocSize = largePageSize;
            }
            else
            {
                nuint factor = array_size_bytes / largePageSize;
                factor += (array_size_bytes % largePageSize > 0) ? (nuint)1: 0;
                allocSize = factor * largePageSize;
            }

            void* x;
            if (write_combine)
            {
                x = PInvoke.VirtualAlloc(null, allocSize, VIRTUAL_ALLOCATION_TYPE.MEM_LARGE_PAGES | VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE, PAGE_PROTECTION_FLAGS.PAGE_READWRITE | PAGE_PROTECTION_FLAGS.PAGE_WRITECOMBINE);
            }
            else if (no_cache)
            {
                x = PInvoke.VirtualAlloc(null, allocSize, VIRTUAL_ALLOCATION_TYPE.MEM_LARGE_PAGES | VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE, PAGE_PROTECTION_FLAGS.PAGE_READWRITE | PAGE_PROTECTION_FLAGS.PAGE_NOCACHE);
            }
            else
            {
                x = PInvoke.VirtualAlloc(null, allocSize, VIRTUAL_ALLOCATION_TYPE.MEM_LARGE_PAGES | VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE, PAGE_PROTECTION_FLAGS.PAGE_READWRITE);
            }

            if (x == null)
            {
                Console.Write("VirtualAlloc() error {0}\n", Marshal.GetLastWin32Error());
                if (!SetPrivilege(hToken, lpszPrivilege, false))
                {
                    Console.Write("SetPrivilege() error {0}\n", Marshal.GetLastWin32Error());
                }
                Environment.Exit(0);
            }

            return (IntPtr)x;
        }
        private unsafe IntPtr _InitSmallPages(uint array_size_bytes, bool no_cache, bool write_combine)
        {
            nuint smallPageSize = 4 * 1024;
            nuint allocSize;
            if (array_size_bytes < smallPageSize)
            {
                allocSize = smallPageSize;
            }
            else
            {
                nuint factor = array_size_bytes / smallPageSize;
                factor += (array_size_bytes % smallPageSize > 0) ? (nuint)1: 0;
                allocSize = factor * smallPageSize;
            }

            void* x;
            if (write_combine)
            {
                x = PInvoke.VirtualAlloc(null, allocSize, VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE, PAGE_PROTECTION_FLAGS.PAGE_READWRITE | PAGE_PROTECTION_FLAGS.PAGE_WRITECOMBINE);
            }
            else if (no_cache)
            {
                x = PInvoke.VirtualAlloc(null, allocSize, VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE, PAGE_PROTECTION_FLAGS.PAGE_READWRITE | PAGE_PROTECTION_FLAGS.PAGE_NOCACHE);
            }
            else
            {
                x = PInvoke.VirtualAlloc(null, allocSize, VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE, PAGE_PROTECTION_FLAGS.PAGE_READWRITE);
            }

            if (x == null)
            {
                Console.Write("VirtualAlloc() error {0}\n", Marshal.GetLastWin32Error());
                Environment.Exit(0);
            }

            return (IntPtr)x;
        }

        unsafe bool SetPrivilege(
            SafeHandle hToken,           // access token handle
            string lpszPrivilege,   // name of privilege to enable/disable
            bool bEnablePrivilege    // to enable (or disable privilege)
        )
        {
            // Token privilege structure
            TOKEN_PRIVILEGES tp;

            // Used by local system to identify the privilege

            if (!PInvoke.LookupPrivilegeValue(
                    null,                // lookup privilege on local system
                    lpszPrivilege,    // privilege to lookup
                    out var luid))               // receives LUID of privilege
            {
                Console.Write("LookupPrivilegeValue() error: {0}\n", Marshal.GetLastWin32Error());
                return false;
            }

            tp.PrivilegeCount = 1;
            tp.Privileges.e0.Luid = luid;

            // Don't forget to disable the privileges after you enabled them,
            // or have already completed your task. Don't mess up your system :o)
            if (bEnablePrivilege)
            {
                tp.Privileges.e0.Attributes = TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED;
            }
            else
            {
                tp.Privileges.e0.Attributes = 0;
            }

            // Enable the privilege (or disable all privileges).
            if (!PInvoke.AdjustTokenPrivileges(
                    hToken,
                    false, // If TRUE, function disables all privileges, if FALSE the function modifies privilege based on the tp
                    &tp,
                    (uint)sizeof(TOKEN_PRIVILEGES),
                    null,
                    null))
            {
                Console.Write("AdjustTokenPrivileges() error: {0}\n", Marshal.GetLastWin32Error());
                return false;
            }
            return true;
        }

        unsafe void _CleanLargePages(IntPtr x)
        {
            if (!SetPrivilege(hToken, lpszPrivilege, false))
            {
                Console.Write("SetPrivilege() error {0}\n", Marshal.GetLastWin32Error());
            }
            if (!PInvoke.VirtualFree((void*)x, 0, VIRTUAL_FREE_TYPE.MEM_RELEASE))
            {
                Console.Write("VirtualFree() error {0}\n", Marshal.GetLastWin32Error());
            }
        }

        unsafe void _CleanSmallPages(IntPtr x)
        {
            if (!PInvoke.VirtualFree((void*)x, 0, VIRTUAL_FREE_TYPE.MEM_RELEASE))
            {
                Console.Write("VirtualFree() error {0}\n", Marshal.GetLastWin32Error());
            }
        }
    }
}
