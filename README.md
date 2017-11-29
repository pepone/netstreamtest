Test case for using .NET Core SSLStream with a certificate chain > 2

## How to use this test
Build and run the server
Build and run the client

On Windows the client output will something similar to

```
Client connected.
Chain length: 2
New Chain length: 3
Certificate error: RemoteCertificateChainErrors
Exception: The remote certificate is invalid according to the validation procedure.
```

That indicates that the length of the chain received is 2
and we are able to build a complete chain using the self
signed CA certificate giving a chain length of 3

On Linux the length of the chain is always 1 indicating that
SslStream is not able to use the Personal store to locate the
intermediate certificate required to build the chain.

