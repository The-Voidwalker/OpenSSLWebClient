using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSSLWebClient.Client
{
    class OpenSSLHttpHandler : HttpMessageHandler
    {
        private bool _disposed = false;
        
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request", "Call to SendAsync with null request.");
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(this.GetType));
            }

            Exception error = ValidateAndNormalizeRequest(request);
            if (error != null)
            {
                return Task.FromException<HttpResponseMessage>(error);
            }

            return null;
        }

        /// <summary>
        /// Validates request and may correct some simple misconfigurations in the request.
        /// </summary>
        /// <remarks>Code based on <c>SocketsHttpHandler.ValidateAndNormalizeRequest</c> for .NET 9</remarks>
        /// <param name="request">HTTP request message to send</param>
        /// <returns>Some Exception describing any problems with the request, or null if no problems exist.</returns>
        private static Exception ValidateAndNormalizeRequest(HttpRequestMessage request)
        {
            Uri requestUri = request.RequestUri;
            if (requestUri is null || !requestUri.IsAbsoluteUri)
            {
                return new InvalidOperationException("Invalid request URI.");
            }

            if (requestUri.Scheme != "https")
            {
                return new InvalidOperationException("OpenSSLWebClient only supports the HTTPS scheme.");
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
