using System;

namespace OpenSSLWebClient.Exceptions
{
    // ---------------------------------------------------------------
    // Interop related exceptions
    // ---------------------------------------------------------------

    /// <summary>
    /// One or more Interop methods failed
    /// </summary>
    public class InteropException : Exception
    {
        public InteropException()
        {
        }

        public InteropException(string message) : base(message)
        {
        }

        public InteropException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
