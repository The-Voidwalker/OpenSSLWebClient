using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OpenSSLWebClient
{
    public static partial class CertificateStore
    {
        /// <summary>
        /// Read the Root X509Store for the CurrentUser and write all certificates in PEM format to CAFile.
        /// </summary>
        /// <remarks>
        /// Only supported on windows platforms.
        /// </remarks>
        internal static void PrepareCAFile()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new PlatformNotSupportedException("CertificateStore.PrepareCAFile is only available on Windows.");
            }
            
            using (X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                StringBuilder pemBuilder = new StringBuilder();
                foreach (X509Certificate2 certificate in store.Certificates)
                {
                    pemBuilder.AppendLine("-----BEGIN CERTIFICATE-----");
                    string append = Convert.ToBase64String(certificate.RawData);
                    int i = 0;
                    for (; i + 64 < append.Length; i += 64)
                    {
                        pemBuilder.AppendLine(append.Substring(i, 64));
                    }
                    pemBuilder.AppendLine(append.Substring(i));
                    pemBuilder.AppendLine("-----END CERTIFICATE-----");
                }
                Directory.CreateDirectory(Path.GetDirectoryName(CAFile));
                File.WriteAllText(CAFile, pemBuilder.ToString(), Encoding.UTF8);
            }
        }
    }
}
