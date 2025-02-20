namespace OpenSSLWebClient
{
    /// <summary>Constants from openssl and linux header files used in calls</summary>
    public class Constants
    {
        public const int AF_INET = 2;
        public const int AF_INET6 = 10;

        /* Socket types, typically use SOCK_STREAM */
        public const int SOCK_STREAM = 1;
        public const int SOCK_DGRAM = 2;

        /* BIO options from openssl/bio.h */
        public const int BIO_NOCLOSE = 0x00;
        public const int BIO_CLOSE = 0x01;

        /* These are technically implemented as an enum, but evaluate to these values */
        public const int BIO_LOOKUP_CLIENT = 0;
        public const int BIO_LOOKUP_SERVER = 1;

        /* BIO Control options */
        public const int BIO_C_SET_CONNECT = 100;
        public const int BIO_C_DO_STATE_MACHINE = 101;
        public const int BIO_C_SET_NBIO = 102;
        public const int BIO_C_SET_FD = 104;
        public const int BIO_C_GET_FD = 105;
        public const int BIO_C_SET_FILE_PTR = 106;
        public const int BIO_C_GET_FILE_PTR = 107;
        public const int BIO_C_SET_FILENAME = 108;
        public const int BIO_C_SET_SSL = 109;
        public const int BIO_C_GET_SSL = 110;
        public const int BIO_C_SET_MD = 111;
        public const int BIO_C_GET_MD = 112;
        public const int BIO_C_GET_CIPHER_STATUS = 113;
        public const int BIO_C_SET_BUF_MEM = 114;
        public const int BIO_C_GET_BUF_MEM_PTR = 115;
        public const int BIO_C_GET_BUFF_NUM_LINES = 116;
        public const int BIO_C_SET_BUFF_SIZE = 117;
        public const int BIO_C_SET_ACCEPT = 118;
        public const int BIO_C_SSL_MODE = 119;
        public const int BIO_C_GET_MD_CTX = 120;
        public const int BIO_C_SET_BUFF_READ_DATA = 122;
        public const int BIO_C_GET_CONNECT = 123;
        public const int BIO_C_GET_ACCEPT = 124;
        public const int BIO_C_SET_SSL_RENEGOTIATE_BYTES = 125;
        public const int BIO_C_GET_SSL_NUM_RENEGOTIATES = 126;
        public const int BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;
        public const int BIO_C_FILE_SEEK = 128;
        public const int BIO_C_GET_CIPHER_CTX = 129;
        public const int BIO_C_SET_BUF_MEM_EOF_RETURN = 130;
        public const int BIO_C_SET_BIND_MODE = 131;
        public const int BIO_C_GET_BIND_MODE = 132;
        public const int BIO_C_FILE_TELL = 133;
        public const int BIO_C_GET_SOCKS = 134;
        public const int BIO_C_SET_SOCKS = 135;
        public const int BIO_C_SET_WRITE_BUF_SIZE = 136;
        public const int BIO_C_GET_WRITE_BUF_SIZE = 137;
        public const int BIO_C_MAKE_BIO_PAIR = 138;
        public const int BIO_C_DESTROY_BIO_PAIR = 139;
        public const int BIO_C_GET_WRITE_GUARANTEE = 140;
        public const int BIO_C_GET_READ_REQUEST = 141;
        public const int BIO_C_SHUTDOWN_WR = 142;
        public const int BIO_C_NREAD0 = 143;
        public const int BIO_C_NREAD = 144;
        public const int BIO_C_NWRITE0 = 145;
        public const int BIO_C_NWRITE = 146;
        public const int BIO_C_RESET_READ_REQUEST = 147;
        public const int BIO_C_SET_MD_CTX = 148;
        public const int BIO_C_SET_PREFIX = 149;
        public const int BIO_C_GET_PREFIX = 150;
        public const int BIO_C_SET_SUFFIX = 151;
        public const int BIO_C_GET_SUFFIX = 152;
        public const int BIO_C_SET_EX_ARG = 153;
        public const int BIO_C_GET_EX_ARG = 154;
        public const int BIO_C_SET_CONNECT_MODE = 155;
        public const int BIO_C_SET_TFO = 156;
        public const int BIO_C_SET_SOCK_TYPE = 157;
        public const int BIO_C_GET_SOCK_TYPE = 158;
        public const int BIO_C_GET_DGRAM_BIO = 159;

        /* BIO Socket options */
        public const int BIO_SOCK_REUSEADDR = 0x01;
        public const int BIO_SOCK_V6_ONLY = 0x02;
        public const int BIO_SOCK_KEEPALIVE = 0x04;
        public const int BIO_SOCK_NONBLOCK = 0x08;
        public const int BIO_SOCK_NODELAY = 0x10;
        public const int BIO_SOCK_TFO = 0x20;

        /* SSL CTRL options, taken from openssl/ssl.h */
        public const int SSL_CTRL_GET_CLIENT_CERT_REQUEST = 9;
        public const int SSL_CTRL_GET_NUM_RENEGOTIATIONS = 10;
        public const int SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS = 11;
        public const int SSL_CTRL_GET_TOTAL_RENEGOTIATIONS = 12;
        public const int SSL_CTRL_GET_FLAGS = 13;
        public const int SSL_CTRL_EXTRA_CHAIN_CERT = 14;
        public const int SSL_CTRL_SET_MSG_CALLBACK = 15;
        public const int SSL_CTRL_SET_MSG_CALLBACK_ARG = 16;
        /* only applies to datagram connections */
        public const int SSL_CTRL_SET_MTU = 17;
        public const int SSL_CTRL_SESS_NUMBER = 20;
        public const int SSL_CTRL_SESS_CONNECT = 21;
        public const int SSL_CTRL_SESS_CONNECT_GOOD = 22;
        public const int SSL_CTRL_SESS_CONNECT_RENEGOTIATE = 23;
        public const int SSL_CTRL_SESS_ACCEPT = 24;
        public const int SSL_CTRL_SESS_ACCEPT_GOOD = 25;
        public const int SSL_CTRL_SESS_ACCEPT_RENEGOTIATE = 26;
        public const int SSL_CTRL_SESS_HIT = 27;
        public const int SSL_CTRL_SESS_CB_HIT = 28;
        public const int SSL_CTRL_SESS_MISSES = 29;
        public const int SSL_CTRL_SESS_TIMEOUTS = 30;
        public const int SSL_CTRL_SESS_CACHE_FULL = 31;
        public const int SSL_CTRL_MODE = 33;
        public const int SSL_CTRL_GET_READ_AHEAD = 40;
        public const int SSL_CTRL_SET_READ_AHEAD = 41;
        public const int SSL_CTRL_SET_SESS_CACHE_SIZE = 42;
        public const int SSL_CTRL_GET_SESS_CACHE_SIZE = 43;
        public const int SSL_CTRL_SET_SESS_CACHE_MODE = 44;
        public const int SSL_CTRL_GET_SESS_CACHE_MODE = 45;
        public const int SSL_CTRL_GET_MAX_CERT_LIST = 50;
        public const int SSL_CTRL_SET_MAX_CERT_LIST = 51;
        public const int SSL_CTRL_SET_MAX_SEND_FRAGMENT = 52;
        public const int SSL_CTRL_SET_TLSEXT_SERVERNAME_CB = 53;
        public const int SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = 54;
        public const int SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
        public const int SSL_CTRL_SET_TLSEXT_DEBUG_CB = 56;
        public const int SSL_CTRL_SET_TLSEXT_DEBUG_ARG = 57;
        public const int SSL_CTRL_GET_TLSEXT_TICKET_KEYS = 58;
        public const int SSL_CTRL_SET_TLSEXT_TICKET_KEYS = 59;
        public const int SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB = 63;
        public const int SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG = 64;
        public const int SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE = 65;
        public const int SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS = 66;
        public const int SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS = 67;
        public const int SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS = 68;
        public const int SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS = 69;
        public const int SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP = 70;
        public const int SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP = 71;
        public const int SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB = 75;
        public const int SSL_CTRL_SET_SRP_VERIFY_PARAM_CB = 76;
        public const int SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB = 77;
        public const int SSL_CTRL_SET_SRP_ARG = 78;
        public const int SSL_CTRL_SET_TLS_EXT_SRP_USERNAME = 79;
        public const int SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH = 80;
        public const int SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD = 81;
        public const int SSL_CTRL_GET_RI_SUPPORT = 76;
        public const int SSL_CTRL_CLEAR_MODE = 78;
        public const int SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB = 79;
        public const int SSL_CTRL_GET_EXTRA_CHAIN_CERTS = 82;
        public const int SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS = 83;
        public const int SSL_CTRL_CHAIN = 88;
        public const int SSL_CTRL_CHAIN_CERT = 89;
        public const int SSL_CTRL_GET_GROUPS = 90;
        public const int SSL_CTRL_SET_GROUPS = 91;
        public const int SSL_CTRL_SET_GROUPS_LIST = 92;
        public const int SSL_CTRL_GET_SHARED_GROUP = 93;
        public const int SSL_CTRL_SET_SIGALGS = 97;
        public const int SSL_CTRL_SET_SIGALGS_LIST = 98;
        public const int SSL_CTRL_CERT_FLAGS = 99;
        public const int SSL_CTRL_CLEAR_CERT_FLAGS = 100;
        public const int SSL_CTRL_SET_CLIENT_SIGALGS = 101;
        public const int SSL_CTRL_SET_CLIENT_SIGALGS_LIST = 102;
        public const int SSL_CTRL_GET_CLIENT_CERT_TYPES = 103;
        public const int SSL_CTRL_SET_CLIENT_CERT_TYPES = 104;
        public const int SSL_CTRL_BUILD_CERT_CHAIN = 105;
        public const int SSL_CTRL_SET_VERIFY_CERT_STORE = 106;
        public const int SSL_CTRL_SET_CHAIN_CERT_STORE = 107;
        public const int SSL_CTRL_GET_PEER_SIGNATURE_NID = 108;
        public const int SSL_CTRL_GET_PEER_TMP_KEY = 109;
        public const int SSL_CTRL_GET_RAW_CIPHERLIST = 110;
        public const int SSL_CTRL_GET_EC_POINT_FORMATS = 111;
        public const int SSL_CTRL_GET_CHAIN_CERTS = 115;
        public const int SSL_CTRL_SELECT_CURRENT_CERT = 116;
        public const int SSL_CTRL_SET_CURRENT_CERT = 117;
        public const int SSL_CTRL_SET_DH_AUTO = 118;
        public const int SSL_CTRL_GET_EXTMS_SUPPORT = 122;
        public const int SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
        public const int SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
        public const int SSL_CTRL_SET_SPLIT_SEND_FRAGMENT = 125;
        public const int SSL_CTRL_SET_MAX_PIPELINES = 126;
        public const int SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE = 127;
        public const int SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB = 128;
        public const int SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG = 129;
        public const int SSL_CTRL_GET_MIN_PROTO_VERSION = 130;
        public const int SSL_CTRL_GET_MAX_PROTO_VERSION = 131;
        public const int SSL_CTRL_GET_SIGNATURE_NID = 132;
        public const int SSL_CTRL_GET_TMP_KEY = 133;
        public const int SSL_CTRL_GET_NEGOTIATED_GROUP = 134;
        public const int SSL_CTRL_GET_IANA_GROUPS = 135;
        public const int SSL_CTRL_SET_RETRY_VERIFY = 136;
        public const int SSL_CTRL_GET_VERIFY_CERT_STORE = 137;
        public const int SSL_CTRL_GET_CHAIN_CERT_STORE = 138;

        /* SSL Error codes from openssl/ssl.h */
        public const int SSL_ERROR_NONE = 0;
        public const int SSL_ERROR_SSL = 1;
        public const int SSL_ERROR_WANT_READ = 2;
        public const int SSL_ERROR_WANT_WRITE = 3;
        public const int SSL_ERROR_WANT_X509_LOOKUP = 4;
        public const int SSL_ERROR_SYSCALL = 5;
        public const int SSL_ERROR_ZERO_RETURN = 6;
        public const int SSL_ERROR_WANT_CONNECT = 7;
        public const int SSL_ERROR_WANT_ACCEPT = 8;
        public const int SSL_ERROR_WANT_ASYNC = 9;
        public const int SSL_ERROR_WANT_ASYNC_JOB = 10;
        public const int SSL_ERROR_WANT_CLIENT_HELLO_CB = 11;
        public const int SSL_ERROR_WANT_RETRY_VERIFY = 12;

        /* SSL Verify options from openssl/ssl.h */
        public const int SSL_VERIFY_NONE = 0x00;
        public const int SSL_VERIFY_PEER = 0x01;
        public const int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
        public const int SSL_VERIFY_CLIENT_ONCE = 0x04;
        public const int SSL_VERIFY_POST_HANDSHAKE = 0x08;

        /* TLS Version numbers, note: versions prior to 1.2 are not included by design */
        public const int TLS1_2_VERSION = 0x0303;
        public const int TLS1_3_VERSION = 0x0304;

        /* TLSEXT option from openssl/tls1.h */
        public const int TLSEXT_NAMETYPE_host_name = 0;

        /* X509 Verification flags from openssl/x509_vfy.h */
        public const int X509_V_OK = 0;
    }
}
