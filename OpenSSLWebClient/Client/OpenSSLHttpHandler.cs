using OpenSSLWebClient.Components;
using OpenSSLWebClient.Exceptions;
using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSSLWebClient.Client
{
    public class OpenSSLHttpHandler : HttpMessageHandler
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

            HttpResponseMessage response = new HttpResponseMessage();

            // TODO: SSL object should be managed in a way that lets us reuse it safely
            using (SSL ssl = new SSL(request.RequestUri.Host, "443"))
            {
                string message = request.Method.Method + " " + request.RequestUri.PathAndQuery
                    + " HTTP/" + request.Version.Major + "." + request.Version.Minor + "\r\n";
                foreach (var rheader in request.Headers)
                {
                    message += rheader.Key + ":" + string.Join(",", rheader.Value.ToArray()) + "\r\n";
                }

                if (request.Content != null)
                {
                    foreach (var cheader in request.Content.Headers)
                    {
                        message += cheader.Key + ":" + string.Join(",", cheader.Value.ToArray()) + "\r\n";
                    }

                    string content = request.Content.ReadAsStringAsync().Result;
                    message += content;  // TODO: ensure message ends with \r\n\r\n in this case
                }

                message += "\r\n";

                ssl.Connect();
                ssl.Write(message);

                byte[] buf = new byte[4098];
                string resp = "";
                int read = 0;

                try
                {
                    while ((read = ssl.Read(ref buf)) > 0)
                    {
                        resp += Encoding.ASCII.GetString(buf, 0, read);
                        // Represents end of response
                        if (resp.Substring(resp.Length - 4) == "\r\n\r\n")
                        {
                            break;
                        }
                    }
                }
                catch (InteropException)
                {
                    // Some failures can be non-fatal. In future, we check those. For now, we cry and move on.
                    throw;
                }

                ByteArrayContent responseContent = new ByteArrayContent(Encoding.UTF8.GetBytes(resp));
                response.Content = responseContent;
            }

            return Task.FromResult(response);
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
