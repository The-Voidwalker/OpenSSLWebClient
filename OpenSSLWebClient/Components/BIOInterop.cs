using System;
using System.Runtime.InteropServices;

namespace OpenSSLWebClient.Components
{
    /// <summary>
    /// Contains all P/Invoke declarations for manipulating BIO objects.
    /// </summary>
    internal static class BIOInterop
    {
        /// <summary>
        /// Performs a lookup to convert a hostname and port into a valid <c>BioAddrInfo</c> object to connect to later.
        /// <see href="https://docs.openssl.org/3.4/man3/BIO_ADDRINFO/"/>
        /// <example> Recommended use:
        /// <code>
        /// IntPtr resPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
        /// BIO_lookup_ex(..., resPtr);
        /// IntPtr res = Marshal.ReadIntPtr(resPtr);
        /// // res is now valid for BIO_ADDRINFO_* calls
        /// </code>
        /// </example>
        /// </summary>
        /// <param name="hostname">Hostname of remote service</param>
        /// <param name="port">Port number for remote service</param>
        /// <param name="lookup_type">Use <c>Constants.BIO_LOOKUP_CLIENT</c></param>
        /// <param name="family">Address family, typically <c>AF_INET</c> or <c>AF_INET6</c></param>
        /// <param name="socktype">Expected socket type, either <c>SOCK_STREAM</c> or <c>SOCK_DGRAM</c></param>
        /// <param name="protocol">Specifies protocol, setting 0 will accept any</param>
        /// <param name="res">Pointer to a pointer to the start of a <c>BIO_ADDRINFO</c> chain</param>
        /// <returns><c>true</c> if operation completed successfully</returns>
        [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern bool BIO_lookup_ex(string hostname, string port, int lookup_type, int family, int socktype, int protocol, IntPtr res);

        /// <summary>
        /// Fetches the pointer of the next <c>BIO_ADDRINFO</c> object in the chain.
        /// <see href="https://docs.openssl.org/3.4/man3/BIO_ADDRINFO/"/>
        /// </summary>
        /// <param name="bai">Pointer to a <c>BIO_ADDRINFO</c> object in unmanaged memory</param>
        /// <returns>
        /// IntPtr.Zero if there is no next <c>BIO_ADDRINFO</c>
        /// </returns>
        /// <remarks>Return case of IntPtr.Zero is untested!</remarks>
        [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr BIO_ADDRINFO_next(IntPtr bai);

        /// <summary>
        /// Returns the address family of the given <c>BIO_ADDRINFO</c>.
        /// <see href="https://docs.openssl.org/3.4/man3/BIO_ADDRINFO/"/>
        /// </summary>
        /// <param name="bai">Pointer to <c>BIO_ADDRINFO</c> object</param>
        /// <returns>One of <c>AF_INET</c>, <c>AF_INET6</c>, and <c>AF_UNIX</c></returns>
        [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int BIO_ADDRINFO_family(IntPtr bai);

        /// <summary>
        /// Gets the <c>BIO_ADDR</c> information from a <c>BIO_ADDRINFO</c> object.
        /// <see href="https://docs.openssl.org/3.4/man3/BIO_ADDRINFO/"/>
        /// </summary>
        /// <param name="bai">Pointer to a <c>BIO_ADDRINFO</c> object</param>
        /// <returns>Pointer to a <c>BIO_ADDR</c> object in unmanaged memory</returns>
        [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr BIO_ADDRINFO_address(IntPtr bai);

        /// <summary>
        /// Frees memory used by a chain of <c>BIO_ADDRINFO</c> objects.
        /// <see href="https://docs.openssl.org/3.4/man3/BIO_ADDRINFO/"/>
        /// </summary>
        /// <param name="bai">Pointer to first <c>BIO_ADDRINFO</c> object in a chain</param>
        [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void BIO_ADDRINFO_free(IntPtr bai);

        /// <summary>
        /// Cross platform method for creating a socket.
        /// <see href="https://docs.openssl.org/3.4/man3/BIO_connect/"/>
        /// </summary>
        /// <param name="domain">Best fetched using <c>BIO_ADDRINFO_family</c></param>
        /// <param name="socktype">One of <c>SOCK_STREAM</c> or <c>SOCK_DGRAM</c></param>
        /// <param name="protocol">Setting to 0 accepts any protocol</param>
        /// <param name="options">Unused, set 0</param>
        /// <returns>
        /// Socket number if successful.
        /// -1 on error.
        /// </returns>
        [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int BIO_socket(int domain, int socktype, int protocol, int options);

        /// <summary>
        /// Connects socket to specified address.
        /// <see href="https://docs.openssl.org/3.4/man3/BIO_connect/"/>
        /// </summary>
        /// <param name="sock">Socket number</param>
        /// <param name="addr">Pointer to address information, fetch using <c>BIO_ADDRINFO_address</c></param>
        /// <param name="options">May be zero or any combination of <c>Constants.BIO_SOCK_*</c> constants</param>
        /// <returns>1 on success, 0 on error</returns>
        [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern bool BIO_connect(int sock, IntPtr addr, int options);

        /// <summary>
        /// Closes specified socket.
        /// <see href="https://docs.openssl.org/3.4/man3/BIO_connect/"/>
        /// </summary>
        /// <param name="sock">Socket number</param>
        /// <returns>1 on success, 0 on error, should be safe to discard</returns>
        [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern bool BIO_closesocket(int sock);

        /// <summary>
        /// Returns socket BIO method.
        /// <see href="https://docs.openssl.org/3.4/man3/BIO_s_socket/"/>
        /// </summary>
        [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr BIO_s_socket();

        /// <summary>
        /// Creates new <c>BIO</c> object in unmanaged memory.
        /// <see href="https://docs.openssl.org/3.4/man3/BIO_new/"/>
        /// </summary>
        /// <param name="method">Fetch using <see cref="BIO_s_socket"/></param>
        /// <returns>Pointer to new <c>BIO</c> object or <c>IntPtr.Zero</c> on error.</returns>
        /// <remarks>Return of IntPtr.Zero is untested!</remarks>
        [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr BIO_new(IntPtr method);

        /// <summary>
        /// BIO control operation using integer parameters.
        /// <see href="https://docs.openssl.org/3.4/man3/BIO_ctrl/"/>
        /// </summary>
        /// <param name="bio">Pointer to <c>BIO</c> object</param>
        /// <param name="cmd">One of the <c>BIO_C_*</c> <see cref="Constants"/></param>
        /// <param name="larg">First argument</param>
        /// <param name="iarg">Second argument</param>
        /// <returns>Varies based on cmd</returns>
        [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int BIO_int_ctrl(IntPtr bio, int cmd, int larg, int iarg);

        /// <summary>
        /// Attaches file descriptor to BIO.
        /// </summary>
        /// <param name="bio">Pointer to BIO object</param>
        /// <param name="fd">File descriptor number, typically socket number</param>
        /// <param name="flags">Either of <c>BIO_NOCLOSE</c> or <c>BIO_CLOSE</c> <see cref="Constants"/></param>
        /// <returns></returns>
        internal static int BIO_set_fd(IntPtr bio, int fd, int flags)
        {
            return BIO_int_ctrl(bio, Constants.BIO_C_SET_FD, flags, fd);
        }
    }
}
