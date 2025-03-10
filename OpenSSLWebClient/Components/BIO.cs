using OpenSSLWebClient.Exceptions;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace OpenSSLWebClient.Components
{
    public enum BioMethod
    {
        Socket
    }

    /// <summary>
    /// Managed representation of openssl's BIO (basic I/O) c objects.
    /// </summary>
    public class BIO : IDisposable
    {
        private IntPtr _bio;
        private int _fd = -1;
        private bool _disposed = false;
        /// <summary>True when attached to an <see cref="SSL"/> object.</summary>
        /// <remarks>This means the unmanaged object will be freed when <see cref="SSL.Free"/> is called.</remarks>
        private bool _managed = false;

        /// <summary>If the bio is pointed at a valid file descriptor and can likely be used.</summary>
        public bool HasFD => _fd > -1;
        public IntPtr Pointer => _bio;

        /// <summary>
        /// Gets a socket connected to the specified hostname and port.
        /// </summary>
        /// <param name="hostname">Hostname of remote</param>
        /// <param name="port">Port number as a string</param>
        /// <param name="socketType"></param>
        /// <returns>File descriptor (or equivalent) for socket as integer. -1 indicates no socket.</returns>
        // TODO: Add support for choosing address family instead of supplying unspecified directly
        public static int GetSocket(string hostname, string port, SocketType socketType)
        {
            int socket = -1;
            // Prepare for results
            IntPtr resPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));

            // Fetch results and check for validity
            if (!BIOInterop.BIO_lookup_ex(hostname, port, Constants.BIO_LOOKUP_CLIENT,
                Constants.AF_UNSPEC, (int)socketType, 0, resPtr))
            {
                goto CleanAndExit;
            }

            IntPtr addrInfo;
            IntPtr res = Marshal.ReadIntPtr(resPtr);
            // Loop through address lookup results
            for (addrInfo = res; addrInfo != IntPtr.Zero; addrInfo = BIOInterop.BIO_ADDRINFO_next(addrInfo))
            {
                // Attempt to create a socket valid for our purposes
                socket = BIOInterop.BIO_socket(BIOInterop.BIO_ADDRINFO_family(addrInfo), Constants.SOCK_STREAM, 0, 0);
                if (socket == -1)
                {
                    continue;
                }

                // Attempt to connect to the address using the socket
                if (!BIOInterop.BIO_connect(socket, BIOInterop.BIO_ADDRINFO_address(addrInfo), Constants.BIO_SOCK_NODELAY))
                {
                    BIOInterop.BIO_closesocket(socket);
                    socket = -1;
                    continue;
                }

                // Connected socket created, break loop
                break;
            }

            BIOInterop.BIO_ADDRINFO_free(res);
        // Above is not included in label as the variable is not defined or assigned when we goto here.
        CleanAndExit:
            Marshal.FreeHGlobal(resPtr);

            return socket;
        }

        /// <summary>
        /// Constructs a new BIO with a stream type socket connected to the specified hostname and port.
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="port"></param>
        /// <returns></returns>
        /// <exception cref="InteropException">Thrown if no valid socket can be found</exception>
        public static BIO NewWithTCPSocket(string hostname, string port)
        {
            BIO bio = new BIO(method: BioMethod.Socket);
            int socket = GetSocket(hostname, port, SocketType.Stream);
            if (socket == -1)
            {
                throw new InteropException("Could not create a valid socket");
            }
            bio.SetFD(socket, Constants.BIO_CLOSE);
            return bio;
        }

        public BIO(BioMethod method = BioMethod.Socket)
        {
            IntPtr meth;
            switch (method)
            {
                case BioMethod.Socket:
                    meth = BIOInterop.BIO_s_socket();
                    break;
                default:
                    throw new ArgumentException("Unsupported BioMethod " + method);
            }
            _bio = BIOInterop.BIO_new(meth);
        }

        /// <summary>
        /// Sets the file descriptor to be used by the BIO using the specified close flag.
        /// </summary>
        /// <param name="fd">File descriptor</param>
        /// <param name="flag">One of <see cref="Constants.BIO_CLOSE"/> or <see cref="Constants.BIO_NOCLOSE"/></param>
        /// <returns></returns>
        public bool SetFD(int fd, int flag = Constants.BIO_CLOSE)
        {
            _fd = fd;
            return BIOInterop.BIO_set_fd(_bio, fd, flag) == 1;
        }

        /// <summary>
        /// This method is called by <see cref="SSL.SetBio"/> to let us know the unmanaged resource will be freed
        /// during <see cref="SSL.Free"/>.
        /// </summary>
        protected internal void Manage()
        {
            _managed = true;
        }

        /// <summary>
        /// Frees the unmanaged object if and only if <see cref="_managed"/> is false.
        /// Call <see cref="Dispose"/> instead.
        /// </summary>
        private void Free()
        {
            Debug.Assert(!_managed, "BIO is mangaged by another object and MUST NOT attempt to free unmanaged resources itself.");
            if (!_managed)
            {
                BIOInterop.BIO_free(_bio);
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // No managed resources to dispose currently
                }
                // Only free unmanaged resources if they won't be freed already.
                if (!_managed)
                {
                    Free();
                }
                _bio = IntPtr.Zero;
                _fd = -1;
                _disposed = true;
            }
        }

        ~BIO()
        {
            Dispose(disposing: false);
        }
    }
}
