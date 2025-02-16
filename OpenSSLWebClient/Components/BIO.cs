using OpenSSLWebClient.Exceptions;
using System;
using System.Runtime.InteropServices;

namespace OpenSSLWebClient.Components
{
    /// <summary>
    /// Contains all P/Invoke declarations for manipulating BIO objects.
    /// </summary>
    internal class BIOInterop
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

    /// <summary>
    /// Manages representation of BIO (basic I/O) c objects.
    /// </summary>
    /// <remarks>
    /// This specific implementation is for a BIO object over a TCP stream socket.
    /// </remarks>
    public class BIO : IDisposable
    {
        private protected IntPtr _bio;
        private protected int _socket;
        private bool disposed = false;

        public readonly string hostname;
        public readonly string port;

        /// <summary>
        /// Pointer to unmanaged BIO object.
        /// </summary>
        public IntPtr Pointer => _bio;
        public bool HasBIO => _bio != IntPtr.Zero;
        public bool HasSocket => _socket != -1;

        // TODO: disentangle BIO and socket handling
        public BIO(string hostname, string port)
        {
            this.hostname = hostname;
            this.port = port;
            _socket = -1;
            _bio = IntPtr.Zero;
            CreateSocket();
            CreateBIO();
        }

        /// <summary>
        /// Called by constructor. Creates a BIO and attaches it to a socket.
        /// </summary>
        /// <remarks>
        /// <see cref="CreateSocket"/> MUST be called before this method.
        /// </remarks>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="InteropException"></exception>
        protected void CreateBIO()
        {
            if (!HasSocket)
            {
                throw new InvalidOperationException("Cannot create a BIO without a socket!");
            }

            _bio = BIOInterop.BIO_new(BIOInterop.BIO_s_socket());
            if (!HasBIO)
            {
                CloseSocket();
                throw new InteropException("Could not create a new BIO!");
            }

            // Attach socket to BIO, flag will close socket when BIO is closed.
            BIOInterop.BIO_set_fd(_bio, _socket, Constants.BIO_CLOSE);
        }

        /// <summary>
        /// Called by constructor. Creates a new socket for use by the BIO. The socket number is stored internally.
        /// </summary>
        /// <remarks>
        /// <see cref="InteropException"/> Can be thrown when a socket is created but failed to connect to the remote server!
        /// </remarks>
        /// <param name="strict">
        /// Determines if an <c>InvalidOperationException</c> will be thrown if attempting to create a socket when one already exists,
        /// silently closes existing socket otherwise
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// Thrown when attempting to create a socket when one already exists and strict is true.
        /// </exception>
        /// <exception cref="InteropException">
        /// Thrown when no socket could be created.
        /// </exception>
        protected void CreateSocket(bool strict = true)
        {
            if (HasSocket)
            {
                if (strict)
                    throw new InvalidOperationException("A socket is already created! Use existing socket or close it first.");
                CloseSocket();
            }

            CreateSocketInternal();
            if (!HasSocket)
            {
                throw new InteropException("Could not create a socket!");
            }
        }

        /// <summary>
        /// Closes attached socket.
        /// </summary>
        /// <param name="strict">Throws <c>InvalidOperationException</c> when strict is true and no socet is currently attached.</param>
        /// <exception cref="InvalidOperationException">
        /// Thrown when no socket is in use and the strict parameter is true.
        /// </exception>
        protected void CloseSocket(bool strict = false)
        {
            if (!HasSocket)
            {
                if (strict)
                    throw new InvalidOperationException("No socket attached to this object!");
                return;
            }
            BIOInterop.BIO_closesocket(_socket);
            _socket = -1;
        }

        /// <summary>
        /// Does the work for creating a socket. Note that the socket may not be successfully created,
        /// and you should always check <see cref="HasSocket"/> after calling this function.
        /// </summary>
        private protected void CreateSocketInternal()
        {
            // Prepare for results
            IntPtr resPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            
            // Fetch results and check for validity
            if (!BIOInterop.BIO_lookup_ex(hostname, port, Constants.BIO_LOOKUP_CLIENT,
                Constants.AF_INET, Constants.SOCK_STREAM, 0, resPtr))
            {
                // Cleanup  TODO: Dedupe cleanup here and at the end of the function
                Marshal.FreeHGlobal(resPtr);
                return;
            }

            IntPtr addrInfo;
            IntPtr res = Marshal.ReadIntPtr(resPtr);
            // Loop through address lookup results
            for (addrInfo = res; addrInfo != IntPtr.Zero; addrInfo = BIOInterop.BIO_ADDRINFO_next(addrInfo))
            {
                // Attempt to create a socket valid for our purposes
                _socket = BIOInterop.BIO_socket(BIOInterop.BIO_ADDRINFO_family(addrInfo), Constants.SOCK_STREAM, 0, 0);
                if (_socket == -1)
                {
                    continue;
                }

                // Attempt to connect to the address using the socket
                if (!BIOInterop.BIO_connect(_socket, BIOInterop.BIO_ADDRINFO_address(addrInfo), Constants.BIO_SOCK_NODELAY))
                {
                    CloseSocket();
                    continue;
                }

                // Connected socket created, break loop
                break;
            }

            // Cleanup  TODO: Dedupe cleanup here and at the early return
            BIOInterop.BIO_ADDRINFO_free(res);
            Marshal.FreeHGlobal(resPtr);
        }

        /// <inheritdoc/>
        /// <remarks>
        /// Note that this method does not free the underlying c object,
        /// as that should be done by the <see cref="SSL"/> layer.
        /// See <see href="https://docs.openssl.org/3.4/man3/SSL_free/#notes"/>
        /// </remarks>
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        /// <inheritdoc cref="Dispose"/>
        /// <param name="disposing">True when disposing, false during finalization.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    // No managed resources
                    // This block is kept for future proofing (hopefully)
                }

                _bio = IntPtr.Zero;
                _socket = -1;
                disposed = true;
            }
        }

        ~BIO()
        {
            Dispose(disposing: false);
        }
    }
}
