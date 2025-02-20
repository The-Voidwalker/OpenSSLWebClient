using OpenSSLWebClient.Components;
using OpenSSLWebClient.Exceptions;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSSLWebClient.Client
{
    internal class HeaderCollection : HttpHeaders
    {
    }
    
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

            HttpResponseMessage response = new HttpResponseMessage() { RequestMessage = request };

            // TODO: SSL object should be managed in a way that lets us reuse it safely
            using (SSL ssl = new SSL(request.RequestUri.Host, "443"))
            {
                string message = request.Method.Method + " " + request.RequestUri.PathAndQuery
                    + " HTTP/" + request.Version.Major + "." + request.Version.Minor + "\r\n";
                foreach (var rheader in request.Headers)
                {
                    message += rheader.Key + ":" + string.Join(", ", rheader.Value.ToArray()) + "\r\n";
                }

                if (request.Content != null)
                {
                    foreach (var cheader in request.Content.Headers)
                    {
                        message += cheader.Key + ":" + string.Join(", ", cheader.Value.ToArray()) + "\r\n";
                    }

                    string content = request.Content.ReadAsStringAsync().Result;
                    message += content;  // TODO: ensure message ends with \r\n\r\n in this case?
                }

                message += "\r\n";

                ssl.Connect();
                ssl.Write(message);

                string headers = TryReadBlock(ssl);

                // TODO: validate we've got enough for the status line before grabbing it like this!
                int newLineIndex = headers.IndexOf('\n');
                string statusLine = headers.Substring(0, newLineIndex);
                headers = headers.Substring(newLineIndex + 1).Trim();
                ParseStatusLine(statusLine, response);
                HeaderCollection contentHeaders = ParseHeaders(headers, response);

                string resp = "";
                if (contentHeaders.Contains("Content-Type"))
                {
                    if (contentHeaders.Contains("ContentLength"))
                    {
                        resp = TryReadBlock(ssl, int.Parse(contentHeaders.GetValues("Content-Length").First()));
                    }
                    else if ((bool)response.Headers.TransferEncodingChunked)
                    {
                        int nextSize = 1;
                        string block = "";
                        bool newBlock = true;

                        while (nextSize > 0)
                        {
                            block = TryReadBlock(ssl, nextSize);
                            if (block.Length < nextSize)
                            {
                                resp += block;
                                nextSize -= block.Length;
                            }
                            else if (block.Length > nextSize)
                            {
                                if (newBlock)
                                {
                                    nextSize = 0;
                                    newBlock = false;
                                }
                                resp += block.Substring(0, nextSize);
                                int nextLine = block.IndexOf('\n', nextSize);
                                if (nextLine > 0 && nextLine < block.Length - 1)
                                {
                                    nextSize = int.Parse(block.Substring(nextSize, nextLine - nextSize).Trim(), System.Globalization.NumberStyles.HexNumber);
                                    block = block.Substring(nextLine).TrimStart();
                                    resp += block;
                                    nextSize -= block.Length;
                                }
                                else
                                {
                                    nextSize = 1;
                                    newBlock = true;
                                }
                            }
                        }
                    }
                    else
                    {
                        throw new HttpRequestException("Invalid response, don't know how to unpack content of type "
                            + string.Join(", ", contentHeaders.GetValues("Content-Type").ToArray()));
                    }

                    ByteArrayContent responseContent = new ByteArrayContent(Encoding.UTF8.GetBytes(resp));
                    foreach (var respContentHeader in contentHeaders)
                    {
                        responseContent.Headers.Add(respContentHeader.Key, respContentHeader.Value);
                    }
                    response.Content = responseContent;
                }
            }

            return Task.FromResult(response);
        }

        private static string TryReadBlock(SSL ssl, int maxRead = 0)
        {
            string resp = "";
            int read = 0;
            int totalRead = 0;
            byte[] buf = new byte[4098];
            do
            {
                try
                {
                    read = ssl.Read(ref buf); // Check read == 0 here?
                    totalRead += read;
                    resp += Encoding.ASCII.GetString(buf, 0, read);
                }
                catch (InteropException e)
                {
                    if (e.Module == "ssl" && e.ModuleCode == Constants.SSL_ERROR_ZERO_RETURN)
                    {
                        break; // SSL connection is closed
                        // TODO: relay this information upward, as this may be unexpected
                    }
                }
                if (resp.Substring(resp.Length - 4) == "\r\n\r\n")
                {
                    break;
                }
            }
            while (read > 0 && (maxRead == 0 || maxRead >= totalRead));
            return resp;
        }

        private static HeaderCollection ParseHeaders(string headerString, HttpResponseMessage response)
        {
            HeaderCollection contentHeaders = new HeaderCollection();
            foreach (string line in headerString.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            {
                int cindex = line.IndexOf(':');
                if (cindex < 0)
                {
                    ThrowInvalid(line);
                }
                
                string key = line.Substring(0, cindex);
                string value = line.Substring(cindex + 1).Trim();
                try
                {
                    response.Headers.Add(key, value);
                }
                catch (InvalidOperationException)
                {
                    // We can't store content headers in response.Content until we have content, which we don't know about yet
                    contentHeaders.Add(key, value);
                }
            }

            return contentHeaders;

            void ThrowInvalid(string line)
            {
                throw new HttpRequestException("Invalid header line in response: \"" + line + "\"");
            }
        }

        private static void ParseStatusLine(string statusLine, HttpResponseMessage response)
        {
            // We expect the HTTP version to be 1.0 or 1.1 as this is all that is supported
            statusLine = statusLine.Trim();

            // Minimum length as HTTP/1.x 123
            const int MinLineLength = 12;
            if (statusLine.Length < MinLineLength
                || statusLine.Substring(0, 7) != "HTTP/1."
                || !char.IsDigit(statusLine[7])
                || statusLine[8] != ' ')
            {
                ThrowInvalid();
            }
            response.Version = new Version(1, statusLine[7] - '0');

            char stat1 = statusLine[9], stat2 = statusLine[10], stat3 = statusLine[11];
            if (!(char.IsDigit(stat1)
                && char.IsDigit(stat2)
                && char.IsDigit(stat3)))
            {
                ThrowInvalid();
            }
            response.StatusCode = (HttpStatusCode)(100 * (stat1 - '0') + 10 * (stat2 - '0') + (stat3 - '0'));

            if (statusLine.Length > MinLineLength + 1)
            {
                if (statusLine[MinLineLength] != ' ')
                {
                    ThrowInvalid();
                }
                response.ReasonPhrase = statusLine.Substring(MinLineLength + 1);
            }
            else
            {
                response.ReasonPhrase = string.Empty;
            }

            void ThrowInvalid()
            {
                throw new HttpRequestException("Received invalid status line from server + \"" + statusLine + "\"");
            }
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
