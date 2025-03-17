using System;

namespace OpenSSLWebClient.Client.Connection
{
    internal readonly struct ConnectionKey : IEquatable<ConnectionKey>
    {
        public readonly string Host;
        public readonly string Port;

        public ConnectionKey(string host, string port)
        {
            Host = host;
            Port = port;
        }

        public override int GetHashCode()
        {
            return Host.GetHashCode() ^ Port.GetHashCode();
        }

        public override bool Equals(object obj)
        {
            return obj is ConnectionKey ckey && Equals(ckey);
        }

        public bool Equals(ConnectionKey other)
        {
            return Host == other.Host && Port == other.Port;
        }
    }
}
