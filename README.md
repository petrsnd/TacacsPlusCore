[![Build status](https://img.shields.io/appveyor/build/petrsnd/TacacsPlusCore)](https://ci.appveyor.com/project/petrsnd/tacacspluscore)
[![nuget](https://img.shields.io/nuget/v/TacacsPlusCore)](https://www.nuget.org/packages/TacacsPlusCore)
[![License](https://img.shields.io/github/license/petrsnd/TacacsPlusCore)](https://github.com/petrnsd/TacacsPlusCore/blob/master/LICENSE)


# TacacsPlusCore
Simple .NET TACACS+ client library

Currently only supports Authentication requests.  Support could be added for Authorization and Accounting.

Algorithms are implemented for CHAP, MS-CHAPv1, and MS-CHAPv2:
- CHAP has been tested against Cisco ISE and TACACS.net
- MS-CHAPv1 has been tested against Cisco ISE
- MS-CHAPv2 In RFC 8907, it is not clear how the "received" challenge and peer challenge are sent in the request, and CISCO ISE does not allow MS-CHAPv2

Calling the API to Authenticate is super simple.

```C#
// supports both IP address and DNS name
// you can use var sharedSecret.ToSecureString() to convert a regular string to a SecureString
var client = new TacacsPlusClient("192.168.1.100", 49, sharedSecret);
// Call Authenticate()
bool result = client.Authenticate(TacacsAuthenticationType.Chap, TacacsAuthenticationService.None, "user", password);
// An exception will be thrown if something goes wrong, otherwise true == success and false == fail
```

Future feature:
- Implement TLS when it becomes standard (https://datatracker.ietf.org/doc/draft-ietf-opsawg-tacacs-tls13/)

It's free.  Enjoy!
