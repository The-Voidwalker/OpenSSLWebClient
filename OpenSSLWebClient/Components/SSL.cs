using OpenSSLWebClient.Exceptions;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSLWebClient.Components
{
    /// <summary>
    /// Stores P/Invoke definitions for managing SSL objects
    /// </summary>
    internal class SSLInterop
    {
        /// <summary>
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_new/"/>
        /// </summary>
        /// <returns>Pointer to the TLS client method</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr TLS_client_method();

        /// <summary>
        /// Create new SSL CTX object.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_new/"/>
        /// </summary>
        /// <param name="method">Pointer to SSL method (<see cref="TLS_client_method"/>)</param>
        /// <returns>Pointer to SSL CTX object in unmanaged memory</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr SSL_CTX_new(IntPtr method);

        /// <summary>
        /// Set verification level for SSL objects created by this context.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_set_verify/"/>
        /// </summary>
        /// <param name="ctx">Pointer to SSL CTX object</param>
        /// <param name="verify">
        /// Verification level from <c>SSL_VERIFY_*</c> <see cref="Constants"/>
        /// (see <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_set_verify/#notes"/> for more details)
        /// </param>
        /// <param name="cb">Callback function to be used, can be <c>IntPtr.Zero</c> for no callback</param>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void SSL_CTX_set_verify(IntPtr ctx, int verify, IntPtr cb);

        /// <summary>
        /// Sets SSL CTX object to use default locations for CA certificates.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_load_verify_locations/"/>
        /// </summary>
        /// <param name="ctx">Pointer to SSL CTX object</param>
        /// <returns>1 on successful operation, 0 on error</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_CTX_set_default_verify_paths(IntPtr ctx);

        /// <summary>
        /// Configures minumum protocol version that can be used by a connection
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_set_min_proto_version/"/>
        /// </summary>
        /// <param name="ctx">Pointer to CTX object</param>
        /// <param name="version">Supported <see cref="Constants"/> are <c>TLS1_2_VERSION</c> and <c>TLS1_3_VERSION</c></param>
        /// <returns>1 on success, 0 on failure</returns>
        public static int SSL_CTX_set_min_proto_version(IntPtr ctx, int version)
        {
            return SSL_CTX_ctrl(ctx, Constants.SSL_CTRL_SET_MIN_PROTO_VERSION, version, IntPtr.Zero);
        }

        /// <summary>
        /// Configures maximum protocol version that can be used by a connection
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_set_min_proto_version/"/>
        /// </summary>
        /// <param name="ctx">Pointer to CTX object</param>
        /// <param name="version">Supported <see cref="Constants"/> are <c>TLS1_2_VERSION</c> and <c>TLS1_3_VERSION</c></param>
        /// <returns>1 on success, 0 on failure</returns>
        public static int SSL_CTX_set_max_proto_version(IntPtr ctx, int version)
        {
            return SSL_CTX_ctrl(ctx, Constants.SSL_CTRL_SET_MAX_PROTO_VERSION, version, IntPtr.Zero);
        }

        /// <summary>
        /// Gets minumum protocol version that can be used by a connection
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_set_min_proto_version/"/>
        /// </summary>
        /// <param name="ctx">Pointer to CTX object</param>
        /// <returns>Integer equivalent to TLS1_?_VERSION <see cref="Constants"/></returns>
        public static int SSL_CTX_get_min_proto_version(IntPtr ctx)
        {
            return SSL_CTX_ctrl(ctx, Constants.SSL_CTRL_GET_MIN_PROTO_VERSION, 0, IntPtr.Zero);
        }

        /// <summary>
        /// Gets maximum protocol version that can be used by a connection
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_set_min_proto_version/"/>
        /// </summary>
        /// <param name="ctx">Pointer to CTX object</param>
        /// <returns>Integer equivalent to TLS1_?_VERSION <see cref="Constants"/></returns>
        public static int SSL_CTX_get_max_proto_version(IntPtr ctx)
        {
            return SSL_CTX_ctrl(ctx, Constants.SSL_CTRL_GET_MAX_PROTO_VERSION, 0, IntPtr.Zero);
        }

        /// <summary>
        /// Performs manipulation of SSL CTX objects. Behaves differently depending on supplied cmd.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_ctrl/"/>
        /// </summary>
        /// <param name="ctx">Pointer to SSL CTX object</param>
        /// <param name="cmd">One of the <c>SSL_CTRL_*</c> <see cref="Constants"/></param>
        /// <param name="larg">Integer argument</param>
        /// <param name="parg">Pointer argument</param>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_CTX_ctrl(IntPtr ctx, int cmd, int larg, IntPtr parg);

        /// <summary>
        /// Configures the CAfile and CApath used for validating certificates.
        /// For additional information on CAfile and CApath, review the linked openssl documentation:
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_load_verify_locations"/>
        /// </summary>
        /// <remarks>
        /// Failure occurs when CAfile and CApath are both null, and additionally when processing one of those locations fails.
        /// </remarks>
        /// <param name="ctx">Pointer to SSL CTX object</param>
        /// <param name="CAfile">Path to a PEM encoded file containing one or more certificates</param>
        /// <param name="CApath">Path to a directory containing one or more individually packaged certificates</param>
        /// <returns>
        /// 1 on successful operation, 0 on failure.
        /// </returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_CTX_load_verify_locations(IntPtr ctx, string CAfile, string CApath);

        /// <summary>
        /// Creates new SSL object from supplied context
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_new/"/>
        /// </summary>
        /// <param name="ctx">Pointer to SSL CTX object</param>
        /// <returns>Pointer to SSL object or <c>IntPtr.Zero</c> on failure</returns>
        /// <remarks>Return of <c>IntPtr.Zero</c> is untested!</remarks>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr SSL_new(IntPtr ctx);

        /// <summary>
        /// Configures the BIO(s) to be used by this SSL object.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_set_bio/"/>
        /// </summary>
        /// <remarks>
        /// <c>read_bio</c> and <c>write_bio</c> can (and likely often should) be the same.
        /// </remarks>
        /// <param name="ssl">Pointer to SSL object</param>
        /// <param name="read_bio">Pointer to BIO object used for reads</param>
        /// <param name="write_bio">Pointer to BIO object used for writes</param>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void SSL_set_bio(IntPtr ssl, IntPtr read_bio, IntPtr write_bio);

        /// <summary>
        /// Congigures the server name indication ClientHello extension to contain the specified name.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_set_tlsext_servername_callback/"/>
        /// </summary>
        /// <remarks>
        /// If improperly configured, the server may reject the handshake.
        /// </remarks>
        /// <param name="ssl">Pointer to SSL object</param>
        /// <param name="name">Hostname of remote server</param>
        /// <returns></returns>
        public static int SSL_set_tlsext_host_name(IntPtr ssl, string name)
        {
            return SSL_ctrl(ssl, Constants.SSL_CTRL_SET_TLSEXT_HOSTNAME, Constants.TLSEXT_NAMETYPE_host_name, name); ;
        }

        /// <summary>
        /// Performs manipulation of SSL objects. Behaves differently depending on supplied cmd.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_ctrl/"/>
        /// </summary>
        /// <param name="ctx">Pointer to SSL object</param>
        /// <param name="cmd">One of the <c>SSL_CTRL_*</c> <see cref="Constants"/></param>
        /// <param name="larg">Integer argument</param>
        /// <param name="parg">Pointer argument</param>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_ctrl(IntPtr ssl, int cmd, int larg, string parg);

        /// <summary>
        /// Initiate the TLS/SSL handshake with the remote server.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_connect/"/>
        /// </summary>
        /// <param name="ssl">Pointer to SSL object</param>
        /// <returns>1 on success, 0 on error</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_connect(IntPtr ssl);

        /// <summary>
        /// Obtain the result code for a TLS/SSL operation.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_get_error/"/>
        /// </summary>
        /// <remarks>
        /// Must be called immediately after failure to obtain results.
        /// </remarks>
        /// <param name="ssl">Pointer to SSL object</param>
        /// <param name="ret">Value returned by the previous TLS/SSL function</param>
        /// <returns></returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_get_error(IntPtr ssl, int ret);

        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_get_verify_result(IntPtr ssl);

        /// <summary>
        /// Closes SSL connection with remote server
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_shutdown/"/>
        /// </summary>
        /// <remarks>
        /// Failure can occur whe not all data is read using <see cref="SSL_read_ex"/>
        /// </remarks>
        /// <param name="ssl">Pointer to SSL object</param>
        /// <returns>0 for ongoing but incomplete shutdown, 1 for successful, less than 0 for not successful</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_shutdown(IntPtr ssl);

        /// <summary>
        /// Frees allocated SSL structure, including other items, such as the read and write BIOs.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_free/"/>
        /// </summary>
        /// <param name="ssl">Pointer to SSL object</param>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void SSL_free(IntPtr ssl);

        /// <summary>
        /// Frees allocated SSL context structure.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_free/"/>
        /// </summary>
        /// <param name="ssl">Pointer to SSL CTX object</param>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void SSL_CTX_free(IntPtr ctx);

        /// <summary>
        /// Writes data over the SSL connection.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_write/"/>
        /// </summary>
        /// <param name="ssl">Pointer to SSL object</param>
        /// <param name="buf">Contents to be sent to the peer</param>
        /// <param name="num">Number of bytes to send to the peer</param>
        /// <param name="written">Pointer to an integer that will contain the number of bytes written to the peer</param>
        /// <returns>1 on success, 0 on failure</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_write_ex(IntPtr ssl, string buf, UIntPtr num, IntPtr written);

        /// <summary>
        /// Reads data over the SSL connection.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_read/"/>
        /// </summary>
        /// <param name="ssl">Pointer to SSL object</param>
        /// <param name="buf">Pointer to start of buffer</param>
        /// <param name="num">Maxium bytes to read from the peer</param>
        /// <param name="written">Pointer to an integer that will contain the number of bytes read from the peer</param>
        /// <returns>1 on success, 0 on failure</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_read_ex(IntPtr ssl, IntPtr buf, UIntPtr num, IntPtr readbytes);

        /// <summary>
        /// Configures the hostname that the peer's certificate must contain in order for the certificate to be validated.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_set1_host/"/>
        /// </summary>
        /// <param name="ssl">Pointer to SSL object</param>
        /// <param name="hostname">Expected hostname of server</param>
        /// <returns></returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_set1_host(IntPtr ssl, string hostname);

        /// <summary>
        /// Received TCP records that have been processed and ready to be read are stored in a buffer.
        /// Calling this method before <c>SSL_read</c> will help prevent accidentally blocking on a read with no data.
        /// See also: <see cref="https://docs.openssl.org/3.4/man3/SSL_pending/"/>
        /// </summary>
        /// <param name="ssl">Pointer to SSL object</param>
        /// <returns>Number of bytes buffered and ready for <c>SSL_read</c></returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_pending(IntPtr ssl);

        /// <summary>
        /// Received TCP records that have been processed and ready to be read are stored in a buffer.
        /// Calling this method before <c>SSL_read</c> will help prevent accidentally blocking on a read with no data.
        /// See also: <see cref="https://docs.openssl.org/3.4/man3/SSL_pending/"/>
        /// </summary>
        /// <param name="ssl">Pointer to SSL object</param>
        /// <returns>1 if SSL has pending records ready to read, 0 if not</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_has_pending(IntPtr ssl);
    }

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
        private bool disposed = false;

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
            if (!disposed)
            {
                if (disposing)
                {
                    _bio?.Dispose();
                }

                Shutdown();
                _ctx = _ssl = _rbio = _wbio = IntPtr.Zero;
                _bio = null;
                disposed = true;
            }
        }

        ~SSL()
        {
            Dispose(disposing: false);
        }
    }
}
