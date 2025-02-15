using System;
using System.Runtime.InteropServices;

namespace OpenSSLWebClient
{
    /// <summary>
    /// Documentation incomplete. For a human readable error message, use:
    /// <code>
    /// int e = ERR_get_error();
    /// IntPtr ebuf = Marshal.AllocHGlobal(4096);
    /// UIntPtr limit = (UIntPtr)4098;
    /// ERR_error_string_n(e, ebuf, limit);
    /// string error = Marshal.PtrToStringAnsi(ebuf);
    /// Marshal.FreeHGlobal(ebuf);
    /// </code>
    /// </summary>
    internal class ErrorsInterop
    {
        /// <summary>
        /// Returns numerical error code for the previous failed function call.
        /// </summary>
        /// <remarks>Pulls from an internal error stack.</remarks>
        [DllImport("D:\\git\\autowikibrowser-code-r12773\\AWB\\OpenSSLWebClient\\lib\\libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int ERR_get_error();

        /// <summary>
        /// Fetches a human readable message for the supplied error code.
        /// </summary>
        /// <param name="e">Error code integer</param>
        /// <param name="buf">Pointer to a buffer to store the requested string</param>
        /// <param name="len">Size of <c>buf</c></param>
        [DllImport("D:\\git\\autowikibrowser-code-r12773\\AWB\\OpenSSLWebClient\\lib\\libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void ERR_error_string_n(int e, IntPtr buf, UIntPtr len);

        public static int ERR_GET_LIB(int e)
        {
            if ((e & (((uint)int.MaxValue) + 1)) != 0)
            {
                return 2;
            }
            return (e >> 23) & 0xFF;
        }

        public static int ERR_GET_REASON(int e)
        {
            if ((e & (((uint)int.MaxValue) + 1)) != 0)
            {
                return 0;
            }
            return (int)(e & 0x7FFFFF);
        }

        public static string GetErrorString()
        {
            int e = ERR_get_error();
            IntPtr ebuf = Marshal.AllocHGlobal(4096);
            UIntPtr limit = (UIntPtr)4098;
            ERR_error_string_n(e, ebuf, limit);
            string error = Marshal.PtrToStringAnsi(ebuf);
            Marshal.FreeHGlobal(ebuf);
            return error;
        }
    }
}
