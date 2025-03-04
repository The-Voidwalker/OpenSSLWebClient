using OpenSSLWebClient.Exceptions;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSLWebClient.Components
{
    /// <summary>
    /// Provides the managed representation of a SSL c object.
    /// </summary>
    /// <remarks>The current version only support for TLS 1.2 and higher.</remarks>
    public class SSL : IDisposable
    {
        private IntPtr _ctx;
        private IntPtr _ssl;
        private IntPtr _rbio;
        private IntPtr _wbio;
        private BIO _bio;
        private bool _disposed = false;

        public IntPtr CTXPointer => _ctx;
        public IntPtr Pointer => _ssl;
        /// <summary>
        /// Validates that both read and write BIOs are configured and nonzero.
        /// Does not check the validity of the unmanaged object.
        /// </summary>
        public bool HasBIOs => _rbio != null
                               && _wbio != null
                               && _rbio != IntPtr.Zero
                               && _wbio != IntPtr.Zero;
        /// <summary>
        /// Validates that the pointer to the unmanaged CTX object is configured and nonzero.
        /// Does not check the validity of the unmanaged object.
        /// </summary>
        public bool HasCTX => _ctx != null && _ctx != IntPtr.Zero;
        /// <summary>
        /// Validates that the pointer to the unmanaged SSL object is configured and nonzero.
        /// Does not check the validity of the unmanaged object.
        /// </summary>
        /// <remarks>
        /// This should imply that both <see cref="HasBIOs"/> and <see cref="HasCTX"/> return true,
        /// but this behavior is not guranteed.
        /// </remarks>
        public bool IsReady => _ssl != null && _ssl != IntPtr.Zero;
        /// <summary>
        /// Returns true if SSL connection has buffered bytes ready to be read.
        /// </summary>
        public bool HasPending => IsReady && SSLInterop.SSL_has_pending(_ssl) > 0;

        public readonly string hostname;
        public readonly string port;

        /// <summary>
        /// Create a new SSL object using only a hostname and port.
        /// A <see cref="BIO"/> object will be automatically created.
        /// </summary>
        /// <param name="hostname">Hostname of remote peer</param>
        /// <param name="port">Port of remote service</param>
        public SSL(string hostname, string port)
        {
            this.hostname = hostname;
            this.port = port;

            CreateSSL(); // Also creates missing BIOs and CTX
        }

        /// <summary>
        /// Creates a new <see cref="BIO"/> using the stored hostname and port.
        /// </summary>
        /// <remarks>This should only be called during object creation.</remarks>
        protected void CreateBIO()
        {
            _bio = new BIO(hostname, port);
            _rbio = _bio.Pointer;
            _wbio = _bio.Pointer;
        }

        /// <summary>
        /// Creates and performs initial configuration of SSL CTX.
        /// </summary>
        /// <remarks>This should only be called during object creation.</remarks>
        /// <exception cref="InteropException"></exception>
        protected void CreateCTX()
        {
            _ctx = SSLInterop.SSL_CTX_new(SSLInterop.TLS_client_method());
            if (!HasCTX)
            {
                throw new InteropException("Could not create SSL CTX");
            }

            SSLInterop.SSL_CTX_set_verify(_ctx, Constants.SSL_VERIFY_PEER, IntPtr.Zero);

            string[] verifyLocations = CertificateStore.VerificationLocations();
            if (SSLInterop.SSL_CTX_load_verify_locations(_ctx, verifyLocations[0], verifyLocations[1]) == 0)
            {
                throw new InteropException("Failed to load certificate verify locations " + verifyLocations);
            }

            if (SSLInterop.SSL_CTX_set_min_proto_version(_ctx, Constants.TLS1_2_VERSION) == 0)
            {
                throw new InteropException("Failed to set minimum TLS version");
            }
        }

        /// <summary>
        /// Creates and configures a SSL object.
        /// </summary>
        /// <param name="createMissingCTX">
        /// When true, function will call <see cref="CreateCTX"/> if one is currently missing.
        /// Otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </param>
        /// <param name="createMissingBIOs">
        /// When true, function will call <see cref="CreateBIO"/> if _rbio and _wbio are missing.
        /// Otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </param>
        /// <exception cref="InvalidOperationException">Thrown if no CTX is found</exception>
        /// <exception cref="InteropException"></exception>
        protected void CreateSSL(bool createMissingCTX = true, bool createMissingBIOs = true)
        {
            if (!HasCTX)
            {
                if (createMissingCTX)
                {
                    CreateCTX();
                }
                else
                {
                    throw new InvalidOperationException("Cannot call CreateSSL without an existing CTX!");
                }
            }
            if (!HasBIOs)
            {
                if (createMissingBIOs)
                {
                    CreateBIO();
                }
                else
                {
                    throw new InvalidOperationException("Cannot call CreateSSL without configuring BIOs!");
                }
            }

            _ssl = SSLInterop.SSL_new(_ctx);
            if (_ssl == IntPtr.Zero)
            {
                throw new InteropException("Failed to create SSL object");
            }

            SSLInterop.SSL_set_bio(_ssl, _rbio, _wbio);

            if (SSLInterop.SSL_set_tlsext_host_name(_ssl, hostname) == 0)
            {
                throw new InteropException("Failed to set TLS hostname extension");
            }

            if (SSLInterop.SSL_set1_host(_ssl, hostname) == 0)
            {
                throw new InteropException("Failed to set hostname used in SSL certificate verification");
            }
        }

        protected void FreeCTX()
        {
            SSLInterop.SSL_CTX_free(_ctx);
            _ctx = IntPtr.Zero;
        }

        protected void FreeSSL()
        {
            SSLInterop.SSL_free(_ssl);
            _ssl = IntPtr.Zero;
        }

        public void Connect()
        {
            if (!IsReady)
            {
                throw new InvalidOperationException("SSL object improperly created!");
            }

            if (SSLInterop.SSL_connect(_ssl) == 0)
            {
                throw new InteropException("Failed to connect.");
            }
        }

        /// <summary>
        /// Closes SSL connection and frees underlying SSL and SSL CTX objects.
        /// </summary>
        public void Shutdown()
        {
            SSLInterop.SSL_shutdown(_ssl);
            FreeSSL();
            FreeCTX();
        }

        /// <summary>
        /// Writes the provided string over the SSL connection.
        /// </summary>
        /// <param name="s">String to be written to peer</param>
        /// <exception cref="InteropException">Thrown on SSL_write_ex failure</exception>
        /// <returns>Number of bytes written to the peer.</returns>
        public int Write(string s)
        {
            IntPtr written = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UIntPtr)));
            Marshal.WriteIntPtr(written, IntPtr.Zero);
            int ret = SSLInterop.SSL_write_ex(_ssl, s, (UIntPtr)s.Length, written);
            int readBytes = (int)Marshal.ReadIntPtr(written);
            Marshal.FreeHGlobal(written);
            if (ret == 0)
            {
                int errorCode = SSLInterop.SSL_get_error(_ssl, ret);
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
                throw new InteropException("Failed to read data from SSL", "ssl", errorCode);
            }

            return readBytes;
        }

        /// <summary>
        /// Reads up to 4096 bytes from the peer and returns the ASCII decoded string.
        /// </summary>
        /// <remarks>SSL_read_ex is not guaranteed to produce a legible string.</remarks>
        /// <returns>Raw data from SSL_read_ex converted to a string using <see cref="Encoding.ASCII"/></returns>
        /// <exception cref="InteropException">Thrown on SSL_read_ex failure</exception>
        public string ReadString()
        {
            byte[] buf = new byte[4098];
            int readbytes = Read(ref buf);
            return Encoding.ASCII.GetString(buf, 0, readbytes);
        }

        /// <inheritdoc/>
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
                    _bio?.Dispose();
                }

                Shutdown();
                _ctx = _ssl = _rbio = _wbio = IntPtr.Zero;
                _bio = null;
                _disposed = true;
            }
        }

        ~SSL()
        {
            Dispose(disposing: false);
        }
    }
}
