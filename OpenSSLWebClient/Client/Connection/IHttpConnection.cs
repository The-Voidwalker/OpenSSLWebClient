using OpenSSLWebClient.Components;
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSSLWebClient.Client.Connection
{
    internal abstract class IHttpConnection : IDisposable
    {
        protected SSL _connection;
        protected bool _disposed = false;

        protected bool HasConnection => _connection != null && _connection.IsReady;

        protected internal Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Exception exception = ValidateAndNormalizeRequestGeneral(request);

            if (exception != null)
            {
                throw exception;
            }

            return SendAsyncInternal(request, cancellationToken);
        }

        protected Exception ValidateAndNormalizeRequestGeneral(HttpRequestMessage request)
        {
            if (_disposed)
            {
                return new ObjectDisposedException(GetType().Name);
            }

            if (request == null)
            {
                return new ArgumentNullException(nameof(request));
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

            // TODO: Is this valid/necessary for all HTTP versions?
            if (request.Headers.Host == null)
            {
                request.Headers.Host = requestUri.Host;
            }

            return ValidateAndNormalizeRequest(request);
        }

        protected abstract Task<HttpResponseMessage> SendAsyncInternal(HttpRequestMessage request, CancellationToken cancellationToken);

        protected abstract Exception ValidateAndNormalizeRequest(HttpRequestMessage request);

        public virtual void Dispose()
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
                    _connection.Dispose();
                }
                _connection = null;
                _disposed = true;
            }
        }
    }
}
