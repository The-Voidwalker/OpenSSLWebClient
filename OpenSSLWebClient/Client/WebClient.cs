using System;
using System.Net.Http;

namespace OpenSSLWebClient.Client
{
    /// <summary>
    /// Simple extension of <see cref="HttpClient"/> that uses <see cref="OpenSSLHttpHandler"/>
    /// as its handler by default. Provides no additional methods.
    /// </summary>
    /// <remarks>
    /// Currently does not support the use of <see cref="HttpMessageHandler"/>s other than
    /// <see cref="OpenSSLHttpHandler"/>.
    /// </remarks>
    public class WebClient : HttpClient
    {
        /// <summary>Creates a <c>WebClient</c> with a new <see cref="OpenSSLHttpHandler"/>.</summary>
        public WebClient() : base(new OpenSSLHttpHandler())
        {
        }

        /// <summary>Creates a <c>WebClient</c> using the provided <see cref="OpenSSLHttpHandler"/>.</summary>
        /// <remarks>
        /// This constructor is included to partially support <see cref="HttpClient(HttpMessageHandler)"/>
        /// like construction. However, using arbitrary <c>HttpMessageHander</c> is not supported,
        /// as they would not send/receive HTTP messages using openssl.
        /// </remarks>
        public WebClient(OpenSSLHttpHandler handler) : base(handler)
        {
        }

        /// <summary>Creates a <c>WebClient</c> using the provided <see cref="OpenSSLHttpHandler"/>.</summary>
        /// <remarks>
        /// This constructor is included to partially support <see cref="HttpClient(HttpMessageHandler, bool)"/>
        /// like construction. However, using arbitrary <c>HttpMessageHander</c> is not supported,
        /// as they would not send/receive HTTP messages using openssl.
        /// </remarks>
        public WebClient(OpenSSLHttpHandler handler, bool disposeHandler) : base(handler, disposeHandler)
        {
        }

        /// <summary>
        /// Using an arbitrary <see cref="HttpMessageHandler"/> is not currently supported, as the supplied handler
        /// may implement their own SendAsync, bypassing the use of openssl.
        /// </summary>
        public WebClient(HttpMessageHandler handler) => throw new NotImplementedException();

        /// <inheritdoc cref="WebClient(HttpMessageHandler)"/>
        public WebClient(HttpMessageHandler handler, bool disposeHandler) => throw new NotImplementedException();
    }
}
