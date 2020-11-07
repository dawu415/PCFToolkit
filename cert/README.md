# cert

## What is this
----
cert is a helper tool written in Go and is used to assist in understanding and debugging certificates, specifically in the context of Cloud Foundry. This is not a replacement for openssl. Currently, this only works on Linux and OSX. The x509 library is limited for Windows and not all features of this tool will work properly.

## Features
----
cert currently supports three commands:

- **verify**: Runs a set of verification tests for a certificate for use on PCF. This command will cause the program to return `1` (fail), should any of these tests fail. The tests are:

    - Verifying the certificate trust chain against a set of provided Root CA certificates, if any.

    - Verifying the certificate trust chain against the OS's system trust store.

    - Verifying that the required Cloud Foundry system and app domains exists in the certificate as CN and SANs

    - Verifying that the certificate has not expired and warning on the length of time before expiration (defaults to 6 months)

    - Verifying that the certificate and a given private key matches, if a private key is provided.

- **info**: Displays general certificate and diagnostic information. For example, construction of the chain of trust of a certificate from all provided certificates and those that exist within the OS's system trust store.

- **get-expiring**: Iterates through a set of certificates and determines outputs if they are expiring within the next 6 months (default value). This command will output nothing, if there are no expiring certificates. Use `--expire-warning-time x` to set `x` months look-ahead.  

Each command supports reading in multiple PEM encoded certificates from following sources

- From a file containing a single PEM certificate
- From a file containing multiple PEM certificates
- From a field in a YAML file containing one or more PEM certificates
- From a given host address and port.

cert tool will read in the above PEM certificates and classify those accordingly as root, intermediate or server/self-signed certificates. 

Each command also supports filtering the output result, so it is possible to search for specific certificates or show specific verify or info results. 

## Usage
----

Run `--help`` to retrieve the list of commands, e.g.,

```
./cert verify --help
```

```
./cert info --help
```

1. Running verify against a certificate
```
./cert --cert mycert.pem

---------------------------------------------------------------------
Verifying Certificate Trust Chain using System Root Certificates. - CN=*.x.net
---------------------------------------------------------------------
Task:  Verifying trust chain of mycert.pem
Status:  FAILED!

Cert Signature: MIIF2DC123...110123R111

---------------------------------------------------------------------
Checking PCF SANs on Certificate - CN=*.x.net
---------------------------------------------------------------------
Task:  Checking *.apps.
Status:  FOUND!
Task:  Checking *.sys.
Status:  FOUND!
Task:  Checking *.uaa.sys.
Status:  FOUND!
Task:  Checking *.login.sys.
Status:  FOUND!

Cert Signature: MIIF2DC123...110123R111

---------------------------------------------------------------------
Checking Certificate Expiry - CN=*.x.net
---------------------------------------------------------------------
Task:  Verifying mycert.pem
Valid From:	2019-09-05 20:05:41 +0000 UTC UNTIL 2019-12-04 20:05:41 +0000 UTC

Status:  WARNING - Within the next 6 months, this certificate expires in 89.67 days (2.95 months)


Cert Signature: MIIF2DC123...110123R111

---------------------------------------------------------------------
Checking the certificate and private key match - CN=*.x.net
---------------------------------------------------------------------
Task:  Could not check matching of certificate and private key. Private key not provided.
Status:  NOT CHECKED

Cert Signature: MIIF2DC123...110123R111

```

2. Running info against a host, e.g., www.google.com. Note that the port 443 is optional. If not provided, it will default to port 443. 

```
./cert info --host www.google.com 443

---------------------------------------------------------------------
Details of www.google.com:443
---------------------------------------------------------------------

	Type: Server Certificate

	Subject: CN=www.google.com,O=Google LLC,L=Mountain View,ST=California,C=US

	Issuer: CN=GTS CA 1O1,O=Google Trust Services,C=US

	CN: www.google.com

	SANS:
		 www.google.com

Trust Chain:
.
└── www.google.com:443
    ├── Subject: www.google.com
    ├── Issuer: GTS CA 1O1
    ├───┐
    └── www.google.com:443
        ├── Subject: GTS CA 1O1
        ├── Issuer: GlobalSign
        ├───┐
        └── System Trust Store: GlobalSign
            ├── Subject: GlobalSign
            └── Issuer: GlobalSign


Chained Certificates:

Server Certificate - www.google.com:

-----BEGIN CERTIFICATE-----
MIIEvjCCA6agAwIBAgIQMmxrpNeLCEQIAAAAABG6zjANBgkqhkiG9w0BAQsFADBC
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMw
EQYDVQQDEwpHVFMgQ0EgMU8xMB4XDTE5MDgyMzEwMjIyOFoXDTE5MTEyMTEwMjIy
OFowaDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxFzAVBgNVBAMTDnd3
dy5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhWJg1IbpNRCw
fbnlm0EiCzvUS9evx+Hp7Qh0AQ/nRbRJ/+cTdnq9RGNda1OcyTG/M2nYS0juqkZV
Sw/huffJFKOCAlMwggJPMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEF
BQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQ6u8OySGKLh9CRiXicnHEJwSiV
ATAfBgNVHSMEGDAWgBSY0fhuEOvPm+xgnxiQG6DrfQn9KzBkBggrBgEFBQcBAQRY
MFYwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnBraS5nb29nL2d0czFvMTArBggr
BgEFBQcwAoYfaHR0cDovL3BraS5nb29nL2dzcjIvR1RTMU8xLmNydDAZBgNVHREE
EjAQgg53d3cuZ29vZ2xlLmNvbTAhBgNVHSAEGjAYMAgGBmeBDAECAjAMBgorBgEE
AdZ5AgUDMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwucGtpLmdvb2cvR1RT
MU8xLmNybDCCAQMGCisGAQQB1nkCBAIEgfQEgfEA7wB2AGPy283oO8wszwtyhCdX
azOkjWF3j711pjixx2hUS9iNAAABbL42qeQAAAQDAEcwRQIgHtHFfacjUKQbSHOZ
7k9hTedyoODJeUKjwbNOuL84AgECIQDCJJNJVKGdet3UmQHy/G4Or7CoG2txWNXV
LRjEhJdn8QB1AHR+2oMxrTMQkSGcziVPQnDCv/1eQiAIxjc1eeYQe8xWAAABbL42
qgoAAAQDAEYwRAIgIKBGIPBRyaPCYE7pAhVT/u+xw/KTaP2c/Pr4+E2/364CIA0G
dFIDqCk8MXe58CeP1uZOqkrx7niphCOidoJ5TMIoMA0GCSqGSIb3DQEBCwUAA4IB
AQChUeMbemnGJkJPFpgZt++Ksyafmd9gB+ovq3r8OfR7uM/PRQK7cyPmtO4hOd+g
w3uk2yXqJXeLove5yuCCqI7QaHLcHC7ekvMsxYN0pYeHg8dZG+qKCR95M1B2H7vO
aolwG70CKr/Lrm2HOaQuHOl88tT0dSOea34ElWFqWllJYn5ffnDiAXx85X0M/SRK
i5zWqop4tk2UiYvCNJq/puu4zLMaBZVQNY0bQxLciudZc3MFrFNNl6IcomuDIqYf
iXKZmfquI+yK7WvjguJgm1n7E7iDRhrkzy1WkDMgrj6bhEZwn9kBiEVBX3dPZ4Wc
ibJ31LEp/GFQ1ryrNA7Au2Jj
-----END CERTIFICATE-----


Intermediate Certificate - GTS CA 1O1:

-----BEGIN CERTIFICATE-----
MIIESjCCAzKgAwIBAgINAeO0mqGNiqmBJWlQuDANBgkqhkiG9w0BAQsFADBMMSAw
HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFs
U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNzA2MTUwMDAwNDJaFw0yMTEy
MTUwMDAwNDJaMEIxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3Qg
U2VydmljZXMxEzARBgNVBAMTCkdUUyBDQSAxTzEwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDQGM9F1IvN05zkQO9+tN1pIRvJzzyOTHW5DzEZhD2ePCnv
UA0Qk28FgICfKqC9EksC4T2fWBYk/jCfC3R3VZMdS/dN4ZKCEPZRrAzDsiKUDzRr
mBBJ5wudgzndIMYcLe/RGGFl5yODIKgjEv/SJH/UL+dEaltN11BmsK+eQmMF++Ac
xGNhr59qM/9il71I2dN8FGfcddwuaej4bXhp0LcQBbjxMcI7JP0aM3T4I+DsaxmK
FsbjzaTNC9uzpFlgOIg7rR25xoynUxv8vNmkq7zdPGHXkxWY7oG9j+JkRyBABk7X
rJfoucBZEqFJJSPk7XA0LKW0Y3z5oz2D0c1tJKwHAgMBAAGjggEzMIIBLzAOBgNV
HQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFJjR+G4Q68+b7GCfGJAboOt9Cf0rMB8G
A1UdIwQYMBaAFJviB1dnHB7AagbeWbSaLd/cGYYuMDUGCCsGAQUFBwEBBCkwJzAl
BggrBgEFBQcwAYYZaHR0cDovL29jc3AucGtpLmdvb2cvZ3NyMjAyBgNVHR8EKzAp
MCegJaAjhiFodHRwOi8vY3JsLnBraS5nb29nL2dzcjIvZ3NyMi5jcmwwPwYDVR0g
BDgwNjA0BgZngQwBAgIwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9wa2kuZ29vZy9y
ZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAGoA+Nnn78y6pRjd9XlQWNa7H
TgiZ/r3RNGkmUmYHPQq6Scti9PEajvwRT2iWTHQr02fesqOqBY2ETUwgZQ+lltoN
FvhsO9tvBCOIazpswWC9aJ9xju4tWDQH8NVU6YZZ/XteDSGU9YzJqPjY8q3MDxrz
mqepBCf5o8mw/wJ4a2G6xzUr6Fb6T8McDO22PLRL6u3M4Tzs3A2M1j6bykJYi8wW
IRdAvKLWZu/axBVbzYmqmwkm5zLSDW5nIAJbELCQCZwMH56t2Dvqofxs6BBcCFIZ
USpxu6x6td0V7SvJCCosirSmIatj/9dSSVDQibet8q/7UK4v4ZUN80atnZz1yg==
-----END CERTIFICATE-----


Root CA Certificate - GlobalSign:

<System Root CAs are not extracted>

---------------------------------------------------------------------

---------------------------------------------------------------------
Details of www.google.com:443
---------------------------------------------------------------------

	Type: Intermediate Certificate

	Subject: CN=GTS CA 1O1,O=Google Trust Services,C=US

	Issuer: CN=GlobalSign,OU=GlobalSign Root CA - R2,O=GlobalSign

	CN: GTS CA 1O1

	SANS:


Trust Chain:
.
└── www.google.com:443
    ├── Subject: GTS CA 1O1
    ├── Issuer: GlobalSign
    ├───┐
    └── System Trust Store: GlobalSign
        ├── Subject: GlobalSign
        └── Issuer: GlobalSign


Chained Certificates:

Intermediate Certificate - GTS CA 1O1:

-----BEGIN CERTIFICATE-----
MIIESjCCAzKgAwIBAgINAeO0mqGNiqmBJWlQuDANBgkqhkiG9w0BAQsFADBMMSAw
HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFs
U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNzA2MTUwMDAwNDJaFw0yMTEy
MTUwMDAwNDJaMEIxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3Qg
U2VydmljZXMxEzARBgNVBAMTCkdUUyBDQSAxTzEwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDQGM9F1IvN05zkQO9+tN1pIRvJzzyOTHW5DzEZhD2ePCnv
UA0Qk28FgICfKqC9EksC4T2fWBYk/jCfC3R3VZMdS/dN4ZKCEPZRrAzDsiKUDzRr
mBBJ5wudgzndIMYcLe/RGGFl5yODIKgjEv/SJH/UL+dEaltN11BmsK+eQmMF++Ac
xGNhr59qM/9il71I2dN8FGfcddwuaej4bXhp0LcQBbjxMcI7JP0aM3T4I+DsaxmK
FsbjzaTNC9uzpFlgOIg7rR25xoynUxv8vNmkq7zdPGHXkxWY7oG9j+JkRyBABk7X
rJfoucBZEqFJJSPk7XA0LKW0Y3z5oz2D0c1tJKwHAgMBAAGjggEzMIIBLzAOBgNV
HQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFJjR+G4Q68+b7GCfGJAboOt9Cf0rMB8G
A1UdIwQYMBaAFJviB1dnHB7AagbeWbSaLd/cGYYuMDUGCCsGAQUFBwEBBCkwJzAl
BggrBgEFBQcwAYYZaHR0cDovL29jc3AucGtpLmdvb2cvZ3NyMjAyBgNVHR8EKzAp
MCegJaAjhiFodHRwOi8vY3JsLnBraS5nb29nL2dzcjIvZ3NyMi5jcmwwPwYDVR0g
BDgwNjA0BgZngQwBAgIwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9wa2kuZ29vZy9y
ZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAGoA+Nnn78y6pRjd9XlQWNa7H
TgiZ/r3RNGkmUmYHPQq6Scti9PEajvwRT2iWTHQr02fesqOqBY2ETUwgZQ+lltoN
FvhsO9tvBCOIazpswWC9aJ9xju4tWDQH8NVU6YZZ/XteDSGU9YzJqPjY8q3MDxrz
mqepBCf5o8mw/wJ4a2G6xzUr6Fb6T8McDO22PLRL6u3M4Tzs3A2M1j6bykJYi8wW
IRdAvKLWZu/axBVbzYmqmwkm5zLSDW5nIAJbELCQCZwMH56t2Dvqofxs6BBcCFIZ
USpxu6x6td0V7SvJCCosirSmIatj/9dSSVDQibet8q/7UK4v4ZUN80atnZz1yg==
-----END CERTIFICATE-----


Root CA Certificate - GlobalSign:

<System Root CAs are not extracted>

---------------------------------------------------------------------
```


3. Running info against a certificate field in a yml file, e.g. a director.yml file containing some content such as:

```
properties-configuration:
  security_configuration:
    trusted_certificates: "----- BEGIN CERTIFICATE -----\nMII.........\n----- END CERTIFICATE -----\n----- BEGIN CERTIFICATE ----- \nMII........."
```


```
./cert info --cert-yml-field director.yml /properties-configuration/security_configuration/trusted_certificates

---------------------------------------------------------------------
Details of director.yml--/properties-configuration/security_configuration/trusted_certificates
---------------------------------------------------------------------

        Type: Server Certificate

        Subject: CN=x.net,OU=x,O=x,L=x,ST=Somewhere,C=US

        Issuer: CN=xxRoot,OU=x,O=x,L=x,ST=Somewhere,C=US

        CN: x.net

        SANS:


Trust Chain:
.
└── trusted_certificates
    ├── Subject: x.net
    ├── Issuer: xxRoot
    ├───┐
    └── trusted_certificates
        ├── Subject: xxRoot
        └── Issuer: xxRoot

... 
...
...

```

4. Running get-expiring a host and checking expiring certificates within the next 16 months:

```
./cert get-expiring --host www.google.com 443 --expire-warning-time 16

---------------------------------------------------------------------
www.google.com:443  ----  CN=www.google.com,O=Google LLC,L=Mountain View,ST=California,C=US
---------------------------------------------------------------------

Status: WARNING - Within the next 16 months, this certificate expires in 66.60 days (2.19 months)


Certificate Valid From: 2020-10-20 18:08:34 +0000 UTC To 2021-01-12 18:08:34 +0000 UTC

Time Check Period Length: 16 Months
Time Check Period From: 2020-11-06 21:50:35.048271 -0600 CST m=+0.036010729
Time Check Period To: 2020-11-06 21:50:35.048271 -0600 CST m=+0.036010729

Cert Signature: MIIExzCCA6...+ntlMQtbuk

---------------------------------------------------------------------
www.google.com:443  ----  CN=GTS CA 1O1,O=Google Trust Services,C=US
---------------------------------------------------------------------

Status: WARNING - Within the next 16 months, this certificate expires in 402.84 days (13.24 months)


Certificate Valid From: 2017-06-15 00:00:42 +0000 UTC To 2021-12-15 00:00:42 +0000 UTC

Time Check Period Length: 16 Months
Time Check Period From: 2020-11-06 21:50:35.0487 -0600 CST m=+0.036440073
Time Check Period To: 2020-11-06 21:50:35.0487 -0600 CST m=+0.036440073

Cert Signature: MIIESjCCAz...atnZz1yg==
```
