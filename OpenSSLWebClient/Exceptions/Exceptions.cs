using OpenSSLWebClient.Components;
using System;
using System.Runtime.InteropServices;

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
        private int _eCode;
        private string _eString;
        private bool _retryable = false;
        private readonly string _module;
        private readonly int _moduleCode;

        public int InteropErrorCode => _eCode;
        public string InteropErrorString => _eString;
        /// <value>True if the previous attempted operation is safe to reattempt.</value>
        public bool Retryable => _retryable;
        public string Module => _module;
        public int ModuleCode => _moduleCode;

        /// <summary>
        /// Determines if the provided SSL error code represents an error that can be retried or not.
        /// Logic is based on openssl's documentation for <see cref="SSLInterop.SSL_get_error"/> at
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_get_error/"/>
        /// </summary>
        /// <param name="code">Return of <see cref="SSLInterop.SSL_get_error"/></param>
        /// <returns>true if method can be safely retried, false if not.</returns>
        private bool RetryableSSL(int code)
        {
            switch (code)
            {
                case Constants.SSL_ERROR_NONE:
                case Constants.SSL_ERROR_WANT_READ:
                case Constants.SSL_ERROR_WANT_WRITE:
                case Constants.SSL_ERROR_WANT_CONNECT:
                case Constants.SSL_ERROR_WANT_ACCEPT:
                case Constants.SSL_ERROR_WANT_ASYNC:
                case Constants.SSL_ERROR_WANT_ASYNC_JOB:
                case Constants.SSL_ERROR_WANT_CLIENT_HELLO_CB:
                    return true;
                case Constants.SSL_ERROR_SSL:
                case Constants.SSL_ERROR_SYSCALL:
                default:
                    return false;
            }
        }

        internal void LoadErrorDetails()
        {
            if (_module == "ssl")
            {
                _retryable = RetryableSSL(_moduleCode);
                // No error, no need to fetch additional information
                if (_moduleCode == Constants.SSL_ERROR_NONE)
                {
                    _eCode = 0;
                    return;
                }
            }
            _eCode = ErrorsInterop.ERR_get_error();
            if (_eCode != 0)
            {
                IntPtr ebuf = Marshal.AllocHGlobal(4096);
                UIntPtr limit = (UIntPtr)4098;
                ErrorsInterop.ERR_error_string_n(_eCode, ebuf, limit);
                _eString = Marshal.PtrToStringAnsi(ebuf);
                Marshal.FreeHGlobal(ebuf);
            }
        }
        
        public InteropException()
        {
            LoadErrorDetails();
        }

        public InteropException(string message) : base(message)
        {
            LoadErrorDetails();
        }

        public InteropException(string message, Exception innerException) : base(message, innerException)
        {
            LoadErrorDetails();
        }

        public InteropException(string message, string module, int moduleCode) : base(message)
        {
            _module = module;
            _moduleCode = moduleCode;
            LoadErrorDetails();
        }

        public InteropException(string message, string module, int moduleCode, Exception innerException) : base(message, innerException)
        {
            _module = module;
            _moduleCode = moduleCode;
            LoadErrorDetails();
        }
    }
}
