using OpenSSLWebClient.Components;
using OpenSSLWebClient.Exceptions;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSSLWebClient.Client.Connection
{
    internal class Http1Connection : IHttpConnection
    {
        public Http1Connection(ConnectionKey connectionDetails)
        {
            SSLContext ctx = new SSLContext();
            ctx.SetVerify(SslVerify.Peer);
            CertificateStore.LoadLocations();
            ctx.LoadVerifyLocations(CertificateStore.CAFile, CertificateStore.CAPath);

            _connection = new SSL(ctx);
            _connection.Set1Host(connectionDetails.Host);
            _connection.SetTlsExtHostName(connectionDetails.Host);

            BIO bio = BIO.NewWithTCPSocket(connectionDetails.Host, connectionDetails.Port);
            _connection.SetBio(bio, bio);
            _connection.Connect();

            // TODO: SSLContext will be managed by a ConnectionPool and will exist for the lifetime of the pool
            ctx.Dispose();

            // SSL.Connect should throw any errors for us, but we should be absolutely certain
            Trace.Assert(HasConnection, "Silent connection failure during initialization of " + GetType().Name);
        }
        
        /// <summary>
        /// Attempts to read a "block" of content using the supplied SSL connection.
        /// This function will not return until it reads 0 bytes, the connection is closed,
        /// the last 4 bytes read consist of "\r\n\r\n", or maxRead is reached.
        /// </summary>
        /// <remarks>
        /// maxRead may be misleading, as any extra content read will be included in the returned block.
        /// </remarks>
        /// <param name="ssl"><see cref="SSL"/> object to read from</param>
        /// <param name="maxRead">Maximum number of bytes to read or 0 for unlimited</param>
        /// <returns>Read content encoded as an ASCII string</returns>
        private string TryReadBlock(int maxRead = 0)
        {
            string resp = "";
            int totalRead = 0;
            // TODO: SSL.Read appears to prefer returning the contents of each TCP segment individually,
            // we can probably use a smaller buffer.
            byte[] buf = new byte[4098];
            int read;
            do
            {
                try
                {
                    read = _connection.Read(ref buf); // Check read == 0 here?
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
                    else
                    {
                        throw;
                    }
                }
                if (read > 4 && resp.Substring(resp.Length - 4) == "\r\n\r\n")
                {
                    break;
                }
            }
            while (read > 0 && (maxRead == 0 || maxRead >= totalRead));
            return resp;
        }

        /// <summary>
        /// Attempts to add the HTTP headers included in <c>headerString</c> to <c>response.Headers</c>.
        /// Headers not successfully added there are returned.
        /// </summary>
        /// <remarks>
        /// Returned HeaderCollection can be assumed to contain only content headers, but this is not guaranteed.
        /// A malformed header that gets past our quick validity check may wind up throwing another error from
        /// <see cref="HttpHeaders"/>, likely an <see cref="InvalidOperationException"/>.
        /// </remarks>
        /// <param name="headerString">String consisting of one or more headers separated by newline</param>
        /// <param name="response"><see cref="HttpResponseMessage"/> to add headers to</param>
        /// <exception cref="HttpRequestException">Thrown if an included header has an invalid format.</exception>
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

        protected override Task<HttpResponseMessage> SendAsyncInternal(HttpRequestMessage request, CancellationToken cancellationToken)
        {


            HttpResponseMessage response = new HttpResponseMessage() { RequestMessage = request };

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

            _connection.Write(message);

            // TryReadBlock returns a block after encountering \r\n\r\n, which indicates the end of the headers
            string headers = TryReadBlock();

            int newLineIndex = headers.IndexOf('\n');
            // If we're missing the index, we'll send an empty line to ParseStatusLine, which will throw an exception for us
            string statusLine = headers.Substring(0, newLineIndex < 0 ? 0 : newLineIndex);
            headers = headers.Substring(newLineIndex + 1).Trim();
            ParseStatusLine(statusLine, response);
            // ParseHeaders adds found headers to response.Headers, but any that are failed to be added are returned separately
            // We assume these to be content headers that we can add to response.Content after it is created
            HeaderCollection contentHeaders = ParseHeaders(headers, response);

            string resp = "";
            // Check for content based on existence of Content-Type header
            // TODO: May need different/other check
            if (contentHeaders.Contains("Content-Type"))
            {
                if (contentHeaders.Contains("ContentLength"))
                {
                    // TODO: verify the end of the block is the end of the content
                    resp = TryReadBlock(int.Parse(contentHeaders.GetValues("Content-Length").First()));
                }
                else if ((bool)response.Headers.TransferEncodingChunked)
                {
                    int nextSize = 1;
                    string block = "";
                    bool newBlock = true;

                    /*
                        * When reading for a new chunk, we start by reading a block at least 1 byte long.
                        * TryReadBlock is pretty much guranteed to return a block larger than the maxRead,
                        * up to 4098 bytes larger! Though, in practice it seems more limited to the TCP
                        * record size. Since the SSL connection isn't being reused here,
                        * it is relatively safe to assume the extra content is a part of the message.
                        * Chunk encoded blocks come in the format of "AAAA\r\nContent of 0xAAAA bytes\r\n"
                        * The last chunk should be "0\r\n"
                        */
                    while (nextSize > 0)
                    {
                        block = TryReadBlock(nextSize);
                        if (block.Length < nextSize)
                        {
                            resp += block;
                            nextSize -= block.Length;
                        }
                        else if (block.Length > nextSize)
                        {
                            // nextSize is used to find the index of the next chunk
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
                    // TODO: misleading, we unpack based on Content-Length or Transfer-Encoding: chunked
                    throw new HttpRequestException("Invalid response, don't know how to unpack content of type "
                        + string.Join(", ", contentHeaders.GetValues("Content-Type").ToArray()));
                }

                // TODO: can we create an object for content earlier? Perhaps StreamContent pointed at a stream we write to above?
                ByteArrayContent responseContent = new ByteArrayContent(Encoding.UTF8.GetBytes(resp));
                foreach (var respContentHeader in contentHeaders)
                {
                    responseContent.Headers.Add(respContentHeader.Key, respContentHeader.Value);
                }
                response.Content = responseContent;
            }

            return Task.FromResult(response);
        }

        protected override Exception ValidateAndNormalizeRequest(HttpRequestMessage request)
        {
            if (request.Version.Major != 1 || !(request.Version.Minor == 0 || request.Version.Minor == 1))
            {
                return new InvalidOperationException("Unsupported HTTP version " + request.Version.Major + '.' + request.Version.Minor);
            }

            return null;
        }
    }
}
