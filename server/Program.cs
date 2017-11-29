using System;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace Examples.System.Net
{
    public sealed class SslTcpServer
    {
        public static void RunServer()
        {
            //
            // Load the server certificate.
            //
            // The certification Path includes a intermediary and is as follow:
            //
            // ZeroC Test CA 1
            //  |
            //  ZeroC Test Intermediate CA 1
            //   |
            //   s_rsa_cai1
            //
            // The intermediate CA is bundle with s_rsa_cai1.p12 and is imported
            // in the user personal store, on Windows platforms that is enough
            // for the server to send the intermediate to the peer as part of the
            // certificate chain.
            //
            // On Linux the peer certificate chain received by the peer is always 1
            // the intermeidate CA is not send with the server certificate.
            //
            var cert = new X509Certificate2("s_rsa_cai1.p12", "password", X509KeyStorageFlags.UserKeySet);

            
            X509Store certStore = new X509Store("My", StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadWrite);
            X509Certificate2Collection certs = new X509Certificate2Collection();
            try
            {
                certs.Import("s_rsa_cai1.p12", "password", X509KeyStorageFlags.DefaultKeySet);
                foreach(X509Certificate2 c in certs)
                {
                    certStore.Add(c);
                }

                TcpListener listener = new TcpListener(IPAddress.Any, 10010);
                listener.Start();
                while (true)
                {
                    Console.WriteLine("Waiting for a client to connect...");
                    TcpClient client = listener.AcceptTcpClient();
                    SslStream sslStream = new SslStream(client.GetStream(), false);
                    try
                    {
                        sslStream.AuthenticateAsServer(cert, false, SslProtocols.Tls, false);
                    }
                    catch(AuthenticationException e)
                    {
                        Console.WriteLine("Exception: {0}", e.Message);
                        break;
                    }
                    finally
                    {
                        sslStream.Close();
                        client.Close();
                    }
                }
            }
            finally
            {
                foreach(X509Certificate2 c in certs)
                {
                    certStore.Remove(c);
                }
            }
        }

        public static int Main(string[] args)
        {
            SslTcpServer.RunServer();
            return 0;
        }
    }
}
