[![Build status](https://img.shields.io/appveyor/build/petrsnd/TacacsPlusCore)](https://ci.appveyor.com/project/petrsnd/tacacspluscore)
[![nuget](https://img.shields.io/nuget/vpre/TacacsPlusCore)](https://www.nuget.org/packages/TacacsPlusCore)
[![License](https://img.shields.io/github/license/petrsnd/TacacsPlusCore)](https://github.com/petrnsd/TacacsPlusCore/blob/master/LICENSE)


# <img src="TACACS+.png" width="28" height="28" />  TacacsPlusCore
Simple .NET TACACS+ client library

Currently only supports Authentication requests.  Support could be added for Authorization and Accounting.

Algorithms are implemented for CHAP, MS-CHAPv1, and MS-CHAPv2.  CHAP has been tested against Cisco ISE and is working.

Calling the API to Authenticate is super simple.

```C#
// supports both IP address and DNS name
// you can use var sharedSecret.ToSecureString() to convert a regular string to a SecureString
var client = new TacacsPlusClient("192.168.1.100", 49, sharedSecret);
// Call Authenticate()
bool result = client.Authenticate(TacacsAuthenticationType.Chap, TacacsAuthenticationService.None, "user", password);
// An exception will be thrown if something goes wrong, otherwise true == success and false == fail
```

It's free.  Enjoy!
