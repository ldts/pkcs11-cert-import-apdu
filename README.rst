
Import NXPSE050 Certificates to PKCS#11
=======================================

Intro and Usage
----------------

This Secured Utility allows the user to import pre-provisioned certificates
from the NXP SE050 via OP-TEE into the pkcs11 database.

Requires that OP-TEE configures the APDU PTA.

Examples of usage::

  * Import NXP SE050 Certficate with the id 0xf0000123 into pkcs#11
    import-pkcs11 --import 0xf0000123 --id 45 --pin 87654321

  * Show NXP SE050 Certficate with the id 0xf0000123 on the console
    import-pkcs11 --show 0xf0000123

Have fun::

            _  _
           | \/ |
        \__|____|__/
          |  o  o|           Thumbs Up
          |___\/_|_____||_
          |       _____|__|
          |      |
          |______|
          | |  | |
          | |  | |
          |_|  |_|


Foundries.io
