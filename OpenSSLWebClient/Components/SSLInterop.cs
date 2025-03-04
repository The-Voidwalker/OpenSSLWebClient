using System;
using System.Runtime.InteropServices;

namespace OpenSSLWebClient.Components
{
    /// <summary>
    /// Stores P/Invoke definitions for managing SSL objects
    /// </summary>
    internal static class SSLInterop
    {
        /// <summary>
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_new/"/>
        /// </summary>
        /// <returns>Pointer to the TLS client method</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr TLS_client_method();

        /// <summary>
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_new/"/>
        /// </summary>
        /// <returns>Pointer to the DTLS client method</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr DTLS_client_method();

        /// <summary>
        /// <see href="https://docs.openssl.org/3.4/man3/OSSL_QUIC_client_method/"/>
        /// </summary>
        /// <returns>Pointer to the QUIC client method</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr OSSL_QUIC_client_method();

        /// <summary>
        /// <see href="https://docs.openssl.org/3.4/man3/OSSL_QUIC_client_method/"/>
        /// </summary>
        /// <returns>Pointer to the QUIC client thread method</returns>
        [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr OSSL_QUIC_client_thread_method();

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
        /// Configures minumum protocol version that can be used by a connection.
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
        /// Configures maximum protocol version that can be used by a connection.
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
        /// Gets minumum protocol version that can be used by a connection.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_set_min_proto_version/"/>
        /// </summary>
        /// <param name="ctx">Pointer to CTX object</param>
        /// <returns>Integer equivalent to TLS1_?_VERSION <see cref="Constants"/></returns>
        public static int SSL_CTX_get_min_proto_version(IntPtr ctx)
        {
            return SSL_CTX_ctrl(ctx, Constants.SSL_CTRL_GET_MIN_PROTO_VERSION, 0, IntPtr.Zero);
        }

        /// <summary>
        /// Gets maximum protocol version that can be used by a connection.
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
        /// Closes SSL connection with remote server.
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_shutdown/"/>
        /// </summary>
        /// <remarks>
        /// Failure can occur whe not all data has been read
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
}
