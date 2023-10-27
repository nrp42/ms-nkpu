A hook library for [ISC Kea DHCP](https://www.isc.org/kea/) providing support for [Microsofts BitLocker network unlock protocol](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/network-unlock/).

The specs can be found [here](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nkpu/832d73ae-7ba6-4578-9f8d-ca09adf9c685/)

### Configuration example

THe unlock certificate and its private key can be in the same file, but it hasn't to be.

    "Dhcp{4|6}": {

        "hooks-libraries": [ {
            "library": "/usr/lib64/kea/hooks/libms-nkpu.so",
            "parameters": 
            { 
                "unlock-keys": [
                    {
                        "certfile": "/etc/ssl/nkpu.pem",
                        "keyfile": "/etc/ssl/nkpu.pem"
                    }
                ]
            }
        } ],
    