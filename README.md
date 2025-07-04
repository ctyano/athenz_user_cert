# athenz-user-cert

This is an unofficial repository to provide tools, packages and instructions for [Athenz](https://www.athenz.io).

It is currently owned and maintained by [ctyano](https://github.com/ctyano).

The `athenz-user-cert` interacts with an OAuth 2.0 Identity Provider to obtain an OAuth access token.  
It then communicates with the Certificate Signer API (e.g., [certsigner-envoy](https://github.com/ctyano/certsigner-envoy)) to retrieve an X.509 certificate.  
This certificate is compatible with Athenz and can be used to authenticate the user.  

## How to build

```
make
```

## List of Distributions

### Docker(OCI) Image

[athenz-user-cert](https://github.com/users/ctyano/packages/container/package/athenz-user-cert)

### Executable binaries

https://github.com/ctyano/athenz-user-cert/releases

