# OpenSSLWebClient

This project was created to add support for TLS 1.3 to dotnet on platforms that don't support it. Notably Windows versions prior to Windows 11 or Windows Server 2022 [do not](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-#tls-protocol-version-support) support TLS 1.3. This project aims to improve support by handling web connections with OpenSSL.

Currently the project only supports the Windows platform, however [plans exist](https://github.com/The-Voidwalker/OpenSSLWebClient/issues/2) to add support for other platforms. However, for other platforms, it should be safe to use the default HttpClient, as it uses OpenSSL already.

# License
This project is licensed under [Apache Liscense 2.0](LICENSE.txt) and additionally includes resources from OpenSSL licensed under the same terms.

# Remarks

When using this project, ensure that `libssl-3.dll` and `libcrypto-3.dll` are available in the same directory as your executable. It is easiest to simply copy the included files from [the lib folder](https://github.com/The-Voidwalker/OpenSSLWebClient/tree/master/OpenSSLWebClient/lib). You may however choose to compile OpenSSL yourself. In the future, the program will seek out existing installs of OpenSSL to reduce the need to package the DLLs on platforms where it isn't necessary.

On Windows, the trusted root CAs are imported from the Current User's Root certificate store and packaged into a single PEM file called `certificates.pem` in a `ssl` folder added under the directory containing the executing assembly. For more information, refer to the [CertificateStore](https://github.com/The-Voidwalker/OpenSSLWebClient/tree/master/OpenSSLWebClient/CertificateStore) files.

# Examples
To use OpenSSL, you can either use the included WebClient, or configure a [HttpClient](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclient) to use the OpenSSLHttpHandler.

Using WebClient:
```c#
using OpenSSLWebClient.Client;
using System;
using System.Net.Http;

WebClient client = new WebClient();
// Use WebClient like you would HttpClient
HttpResponseMessage = client.GetAsync("https://example.com");
```

Using HttpClient
```c#
using OpenSSLWebClient.Client;
using System;
using System.Net.Http;

OpenSSLHttpHandler handler = new OpenSSLHttpHandler();
HttpClient client = new HttpClient(handler);
// Use HttpClient as normal
HttpResponseMessage = client.GetAsync("https://example.com");
```
