using System;

namespace OpenSSLWebClient
{
    // ---------------------------------------------------------------
    // BIO related exceptions
    // ---------------------------------------------------------------
    
    /// <summary>
    /// A socket is missing where one is expected.
    /// </summary>
    public class MissingSocketException : ApplicationException
    {
        public MissingSocketException(string message) : base(message)
        {
        }
    }

    // ---------------------------------------------------------------
    // Interop related exceptions
    // ---------------------------------------------------------------
    
    /// <summary>
    /// One or more Interop methods failed
    /// </summary>
    public class InteropException : ApplicationException
    {
        public InteropException(string message) : base(message)
        {
        }
    }
}
