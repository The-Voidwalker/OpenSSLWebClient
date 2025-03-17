using OpenSSLWebClient.Client.Connection;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSSLWebClient.Client
{
    /// <inheritdoc/>
    /// <remarks>Implements <see cref="HttpHeaders"/> with no modifications.</remarks>
    internal class HeaderCollection : HttpHeaders
    {
    }
    
    /// <summary>
    /// Implements <see cref="HttpMessageHandler"/> using openssl to send and receive data.
    /// </summary>
    public class OpenSSLHttpHandler : HttpMessageHandler
    {
        private bool _disposed = false;

        /// <inheritdoc/>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ObjectDisposedException"></exception>
        /// <exception cref="HttpRequestException"></exception>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request", "Call to SendAsync with null request.");
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }

            Exception error = ValidateAndNormalizeRequest(request);
            if (error != null)
            {
                return Task.FromException<HttpResponseMessage>(error);
            }

            ConnectionKey ckey = new ConnectionKey(request.RequestUri.Host, request.RequestUri.Port.ToString());

            Http1Connection connection = new Http1Connection(ckey);

            return connection.SendAsync(request, cancellationToken);
        }

        /// <summary>
        /// Validates request and may correct some simple misconfigurations in the request.
        /// </summary>
        /// <remarks>Code based on <c>SocketsHttpHandler.ValidateAndNormalizeRequest</c> for .NET 9</remarks>
        /// <param name="request">HTTP request message to send</param>
        /// <returns>Some Exception describing any problems with the request, or null if no problems exist.</returns>
        private static Exception ValidateAndNormalizeRequest(HttpRequestMessage request)
        {
            if (request.Version.Major != 1 || !(request.Version.Minor == 0 || request.Version.Minor == 1))
            {
                return new InvalidOperationException("Unsupported HTTP version " + request.Version.Major + '.' + request.Version.Minor);
            }
            Uri requestUri = request.RequestUri;
            if (requestUri is null || !requestUri.IsAbsoluteUri)
            {
                return new InvalidOperationException("Invalid request URI.");
            }

            if (requestUri.Scheme != "https")
            {
                return new InvalidOperationException("OpenSSLWebClient only supports the HTTPS scheme.");
            }

            if (request.Headers.Host == null)
            {
                request.Headers.Host = requestUri.Host;
            }

            return null;
        }

        public new void Dispose() => Dispose(disposing: true);

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _disposed = true;
        }

        ~OpenSSLHttpHandler()
        {
            Dispose(disposing: false);
        }
    }
}
