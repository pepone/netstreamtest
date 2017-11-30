using System;
using System.Collections;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace Examples.System.Net
{
    public class SslTcpClient
    {
        private static Hashtable certificateErrors = new Hashtable();

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(object sender,
                                                     X509Certificate certificate,
                                                     X509Chain chain,
                                                     SslPolicyErrors sslPolicyErrors)
        {
            //
            // We expect the received chain lenght to be 2, it should contain the Intermediate
            // CA but not the Root CA
            //
            Console.WriteLine("Chain length: {0}", chain.ChainElements.Count);
            var newChain = new X509Chain(false);
            newChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            newChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            //
            // Add the required itermediate certificates to the extra store
            // so that they can be used when building the chain
            //
            foreach(var e in chain.ChainElements)
            {
                // In a real case we would need to check that we are not adding the XSRoot CA
                newChain.ChainPolicy.ExtraStore.Add(e.Certificate);
            }
            // Add our Self signed CA certificate to build the newChain
            newChain.ChainPolicy.ExtraStore.Add(new X509Certificate2("cacert1.der"));
            newChain.Build(new X509Certificate2(certificate));

            Console.WriteLine("New Chain length: {0}", newChain.ChainElements.Count);
            if(sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }

        public static void RunClient(string host)
        {
            TcpClient client = new TcpClient(host, 10010);
            Console.WriteLine("Client connected.");
            SslStream sslStream = new SslStream(client.GetStream(),
                                                false,
                                                new RemoteCertificateValidationCallback (ValidateServerCertificate),
                                                null);
            try
            {
                sslStream.AuthenticateAsClient(host);
            }
            catch(AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                return;
            }
            client.Close();
            Console.WriteLine("Client closed.");
        }

        public static int Main(string[] args)
        {
            string host = args.Length > 0 ? args[0] : "127.0.0.1";
            SslTcpClient.RunClient(host);
            return 0;
        }
    }
}
