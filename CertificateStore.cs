using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace OpenSSLWebClient
{
    /// <summary>
    /// Handles passing trusted certificates to OpenSSL.
    /// </summary>
    /// <remarks>In future versions this will be made to support additional platforms.</remarks>
    public static partial class CertificateStore
    {
        internal static string CAFile = null;
        internal static string CAPath = null;
        internal static bool loaded = false;

        /// <summary>
        /// Perform any necessary setup then load values into one or both of <see cref="CAFile"/> and <see cref="CAPath"/>.
        /// </summary>
        /// <remarks>
        /// Behavior varies depending on the OS.
        /// </remarks>
        internal static void LoadLocations(bool refresh = false)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string basePath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                CAFile = Path.Combine(basePath, "ssl", "certificates.pem");
                if (!File.Exists(CAFile) || refresh)
                {
                    PrepareCAFile();
                }
            }
            else
            {
                throw new PlatformNotSupportedException("Project currently only supports Windows.");
            }
        }

        /// <summary>
        /// Gets both the CAFile and CAPath used by openssl. See
        /// <see href="https://docs.openssl.org/3.4/man3/SSL_CTX_load_verify_locations/#notes"/>
        /// for details about both these values.
        /// </summary>
        /// <remarks>Calls partial method LoadLocations prior to return the first time this method is called.</remarks>
        /// <returns>Array <c>{ CAFile, CAPath }</c> One or both strings may be null.</returns>
        public static string[] VerificationLocations(bool refresh = false)
        {
            if (!loaded || refresh)
            {
                LoadLocations(refresh);
                loaded = true;
            }
            return new string[] { CAFile, CAPath };
        }
    }
}
