using OpenSSLWebClient.Exceptions;
using System;
using System.Runtime.InteropServices;

namespace OpenSSLWebClient.Components
{
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
        private bool _disposed = false;

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
            if (!_disposed)
            {
                if (disposing)
                {
                    // No managed resources
                    // This block is kept for future proofing (hopefully)
                }

                _bio = IntPtr.Zero;
                _socket = -1;
                _disposed = true;
            }
        }

        ~BIO()
        {
            Dispose(disposing: false);
        }
    }
}
