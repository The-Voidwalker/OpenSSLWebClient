using OpenSSLWebClient.Exceptions;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSLWebClient.Components
{
    [Flags]
    public enum SslVerify
    {
        None = Constants.SSL_VERIFY_NONE,
        Peer = Constants.SSL_VERIFY_PEER,
        FailIfNoPeerCert = Constants.SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        ClientOnce = Constants.SSL_VERIFY_CLIENT_ONCE,
        PostHandshake = Constants.SSL_VERIFY_POST_HANDSHAKE,
    }

    public enum SSLMethod
    {
        TLS,
        DTLS,
        QUIC,
        QUIC_thread
    }

    /// <summary>
    /// Managed representation of openssl's SSL_CTX c object.
    /// </summary>
    public class SSLContext : IDisposable
    {
        private IntPtr _ctx;
        private bool _disposed = false;

        public IntPtr Pointer => _ctx;
        public ProtocolVersion MaxProtoVersion => (ProtocolVersion)SSLInterop.SSL_CTX_get_max_proto_version(_ctx);
        public ProtocolVersion MinProtoVersion => (ProtocolVersion)SSLInterop.SSL_CTX_get_min_proto_version(_ctx);

        /// <summary>
        /// Creates a new SSL_CTX targeting the specified method.
        /// </summary>
        /// <param name="method"></param>
        /// <exception cref="ArgumentException"></exception>
        public SSLContext(SSLMethod method = SSLMethod.TLS)
        {
            IntPtr methodPtr;
            switch (method)
            {
                case SSLMethod.TLS:
                    methodPtr = SSLInterop.TLS_client_method();
                    break;
                case SSLMethod.DTLS:
                    methodPtr = SSLInterop.DTLS_client_method();
                    break;
                case SSLMethod.QUIC:
                    methodPtr = SSLInterop.OSSL_QUIC_client_method();
                    break;
                case SSLMethod.QUIC_thread:
                    methodPtr = SSLInterop.OSSL_QUIC_client_thread_method();
                    break;
                default:
                    throw new ArgumentException("Unsupported SSLMethod " + method);
            }
            _ctx = SSLInterop.SSL_CTX_new(methodPtr);
        }

        /// <summary>
        /// Configures the CAfile and CApath used for validating certificates.
        /// For additional information on CAfile and CApath, review the linked openssl documentation:
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_load_verify_locations"/>
        /// </summary>
        /// <remarks>
        /// Failure occurs when CAfile and CApath are both null, and additionally when processing one of those locations fails.
        /// </remarks>
        /// <param name="caFile">Path to a PEM encoded file containing one or more certificates</param>
        /// <param name="caPath">Path to a directory containing one or more individually packaged certificates</param>
        /// <returns>true on successful operation, false on failure</returns>
        public bool LoadVerifyLocations(string caFile, string caPath)
        {
            return SSLInterop.SSL_CTX_load_verify_locations(_ctx, caFile, caPath) == 1;
        }

        /// <summary>
        /// Sets SSL CTX object to use default locations for CA certificates.
        /// Wrapper for <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_load_verify_locations/"/>
        /// </summary>
        /// <returns>true on success, false if an error was encountered</returns>
        public bool SetDefaultVerifyPaths()
        {
            return SSLInterop.SSL_CTX_set_default_verify_paths(_ctx) == 1;
        }

        /// <summary>
        /// Configures maximum protocol version that can be used in a connection.
        /// </summary>
        /// <param name="version">Maxium protocol version</param>
        /// <returns>true on success, false if an error was encountered</returns>
        public bool SetMaxProtoVersion(ProtocolVersion version)
        {
            return SSLInterop.SSL_CTX_set_max_proto_version(_ctx, (int)version) == 1;
        }

        /// <summary>
        /// Configures minimum protocol version that can be used in a connection.
        /// </summary>
        /// <param name="version">Minimum protocol version</param>
        /// <returns>true on success, false if an error was encountered</returns>
        public bool SetMinProtoVersion(ProtocolVersion version)
        {
            return SSLInterop.SSL_CTX_set_min_proto_version(_ctx, (int)version) == 1;
        }

        /// <summary>
        /// Set verification level for SSL objects created by this context.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_set_verify/"/>
        /// </summary>
        /// <remarks>
        /// For clients, any combination of flags not equivalent to <c>SslVerify.None</c>
        /// is treated the same as <c>SslVerify.Peer</c>. For more details, see
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_set_verify/#bugs"/>
        /// </remarks>
        /// <param name="verify">Verification level as a combination of <see cref="SslVerify"/> flags</param>
        public void SetVerify(SslVerify verify)
        {
            SSLInterop.SSL_CTX_set_verify(_ctx, (int)verify, IntPtr.Zero);
        }

        /// <summary>
        /// Frees unmanaged resources. Call <see cref="Dispose"/> instead.
        /// </summary>
        private void Free()
        {
            SSLInterop.SSL_CTX_free(_ctx);
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
                    // No current managed resources to dispose.
                }
                Free();
                _ctx = IntPtr.Zero;
                _disposed = true;
            }
        }

        ~SSLContext()
        {
            Dispose(disposing: false);
        }
    }

    /// <summary>
    /// Managed representation of openssl's SSL c object.
    /// </summary>
    public class SSL : IDisposable
    {
        private SSLContext _ctx;
        /// <summary>Pointer to unmanaged object.</summary>
        private IntPtr _ssl;
        /// <summary>Read BIO.</summary>
        private BIO _rbio;
        /// <summary>Write BIO.</summary>
        private BIO _wbio;
        private bool _disposed = false;
        private bool _closed = false;
        private bool _connected = false;

        /// <inheritdoc cref="_ssl"/>
        public IntPtr Pointer => _ssl;
        public bool HasBios => _rbio != null && _wbio != null;
        // TODO: unneeded? Provide better check elsewhere?
        public bool IsReady => !_disposed && !_closed
            && _ssl != null && _ssl != IntPtr.Zero
            && HasBios;
        /// <summary>Number of bytes ready to be read.</summary>
        public int Pending
        {
            get
            {
                ThrowBadState(hasBios: true, isConnected: true);
                return SSLInterop.SSL_pending(_ssl);
            }
        }
        /// <summary>True when bytes are ready to be read.</summary>
        public bool HasPending => Pending > 0;

        /// <summary>
        /// Creates a new SSL object using the provided context.
        /// </summary>
        /// <param name="ctx"></param>
        /// <exception cref="InteropException"></exception>
        public SSL(SSLContext ctx)
        {
            _ctx = ctx;
            _ssl = SSLInterop.SSL_new(_ctx.Pointer);
            if (_ssl == IntPtr.Zero)
            {
                throw new InteropException("Failed to create unmanaged SSL object");
            }
        }

        /// <summary>
        /// Writes the provided string over the SSL connection.
        /// </summary>
        /// <param name="s">String to be written to peer</param>
        /// <exception cref="InteropException">Thrown on SSL_write_ex failure</exception>
        /// <returns>Number of bytes written to the peer.</returns>
        public int Write(string s)
        {
            ThrowBadState(hasBios: true, isConnected: true);
            IntPtr written = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UIntPtr)));
            Marshal.WriteIntPtr(written, IntPtr.Zero);
            int ret = SSLInterop.SSL_write_ex(_ssl, s, (UIntPtr)s.Length, written);
            int readBytes = (int)Marshal.ReadIntPtr(written);
            Marshal.FreeHGlobal(written);
            if (ret == 0)
            {
                int errorCode = SSLInterop.SSL_get_error(_ssl, ret);
                if (errorCode == Constants.SSL_ERROR_ZERO_RETURN)
                {
                    _closed = true;
                }
                throw new InteropException("Failed to write to SSL", "ssl", errorCode);
            }
            return readBytes;
        }

        /// <summary>
        /// Reads bytes into the provided buffer.
        /// </summary>
        /// <remarks>If no pending data is available to be read, this method will immediately return 0.</remarks>
        /// <param name="buf">A span of bytes to write into.</param>
        /// <returns>Number of bytes read as an integer.</returns>
        /// <exception cref="ArgumentException">Thrown when buf is null or of length 0</exception>
        /// <exception cref="InteropException">Thrown on SSL failure, error details are collected and attached to the Exception object</exception>
        public int Read(ref byte[] buf)
        {
            if (buf == null || buf.Length == 0)
            {
                throw new ArgumentException("buf must be non null and have a length greater than zero.");
            }

            ThrowBadState(hasBios: true, isConnected: true);

            if (!HasPending)
            {
                return 0;
            }

            IntPtr readbytesPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UIntPtr)));
            Marshal.WriteIntPtr(readbytesPtr, IntPtr.Zero);

            IntPtr bufPtr = Marshal.AllocHGlobal(Marshal.SizeOf(buf[0]) * buf.Length);

            int ret = SSLInterop.SSL_read_ex(_ssl, bufPtr, (UIntPtr)buf.Length, readbytesPtr);

            int readBytes = (int)Marshal.ReadIntPtr(readbytesPtr);
            Marshal.FreeHGlobal(readbytesPtr);

            if (ret != 0)
            {
                Marshal.Copy(bufPtr, buf, 0, readBytes);
            }

            Marshal.FreeHGlobal(bufPtr);

            if (ret == 0)
            {
                int errorCode = SSLInterop.SSL_get_error(_ssl, ret);
                if (errorCode == Constants.SSL_ERROR_ZERO_RETURN)
                {
                    _closed = true;
                }
                throw new InteropException("Failed to read data from SSL", "ssl", errorCode);
            }

            return readBytes;
        }

        /// <summary>
        /// Initiate the TLS/SSL handshake with the remote server.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown when BIOs are not yet configured</exception>
        /// <exception cref="InteropException"></exception>
        public void Connect()
        {
            ThrowBadState(hasBios: true);
            int ret = SSLInterop.SSL_connect(_ssl);
            if (ret != 1)
            {
                int code = SSLInterop.SSL_get_error(_ssl, ret);
                if (code == Constants.SSL_ERROR_ZERO_RETURN)
                {
                    _closed = true;
                }

                throw new InteropException("Could not connect to remote", "ssl", code);
            }
            _connected = true;
        }

        /// <summary>
        /// Configures the hostname that the peer's certificate must contain in order for the certificate to be validated.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_set1_host/"/>
        /// </summary>
        /// <param name="hostname">Expected hostname of server</param>
        /// <returns>true if successful, false on failure</returns>
        public bool Set1Host(string hostname)
        {
            return SSLInterop.SSL_set1_host(_ssl, hostname) == 1;
        }

        /// <summary>Configures BIO(s) used for i/o operations.</summary>
        /// <remarks><c>readBio</c> and <c>writeBio</c> may be the same.</remarks>
        /// <param name="readBio">BIO used for reading</param>
        /// <param name="writeBio">BIO used for writing</param>
        /// <exception cref="InvalidOperationException">Thrown when BIOs are already set</exception>
        public void SetBio(BIO readBio, BIO writeBio)
        {
            ThrowBadState();
            _rbio = readBio;
            _wbio = writeBio;
            SSLInterop.SSL_set_bio(_ssl, _rbio.Pointer, _wbio.Pointer);
        }

        /// <summary>
        /// Congigures the server name indication ClientHello extension to contain the specified name.
        /// </summary>
        /// <remarks>
        /// If improperly configured, the server may reject the handshake.
        /// </remarks>
        /// <param name="hostname">Hostname of remote server</param>
        /// <returns>true on success, false on failure</returns>
        public bool SetTlsExtHostName(string hostname)
        {
            return SSLInterop.SSL_set_tlsext_host_name(_ssl, hostname) == 1;
        }

        /// <inheritdoc cref="SSLInterop.SSL_shutdown(IntPtr)"/>
        public int Shutdown()
        {
            ThrowBadState(hasBios: true, isConnected: true);
            _closed = true;
            return SSLInterop.SSL_shutdown(_ssl);
        }

        /// <summary>Free unmanaged resources. Call <see cref="Dispose"/> instead.</summary>
        private void Free()
        {
            SSLInterop.SSL_free(_ssl);
        }

        /// <summary>
        /// Throws an exception if the objects state does not match the desired state.
        /// The boolean parameters represent the desired state, for example
        /// <c>hasBios: true</c> throw an exception if BIOs are missing, but
        /// <c>hasBios: false</c> throws an exception if BIOs are present.
        /// </summary>
        /// <exception cref="ObjectDisposedException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        private void ThrowBadState(
            [CallerMemberName] string callerName = "",
            bool hasBios = false,
            bool isConnected = false,
            bool isClosed = false
            )
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
            if (hasBios != HasBios)
            {
                throw new InvalidOperationException("BIOs must" + (hasBios ? " " : " not ") + "be configured before calling " + callerName);
            }
            if (isConnected != _connected)
            {
                throw new InvalidOperationException("Connection must" + (isConnected ? " " : " not ") + "be establised before calling " + callerName);
            }
            if (isClosed != _closed)
            {
                throw new InvalidOperationException("Connection must" + (isConnected ? " " : " not ") + "be closed before calling " + callerName);
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
                    _wbio.Dispose();
                    _rbio.Dispose();
                }
                Free();
                // CTX can be reused by other SSL objects, so we cannot Dispose it.
                _ctx = null;
                _wbio = _rbio = null;
                _ssl = IntPtr.Zero;
                _disposed = true;
            }
        }

        ~SSL()
        {
            Dispose(disposing: false);
        }
    }
}
