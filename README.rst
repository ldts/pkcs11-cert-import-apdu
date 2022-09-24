
Import NXPSE050/51 Certificates to PKCS#11
===========================================

Intro and Usage
----------------

This Secured Utility allows the user to import pre-provisioned certificates
from the NXP SE050/51 via OP-TEE into the pkcs11 database.

If SCP03 was enabled, OP-TEE will take care of encrypt/decrypt and MAC
authenticate the APDUs shared between the processor and the secure element.

Data flow by exception level executing in an ARM host:

  * EL0   [User space  ] Prepares raw APDU frames.
                         Sends the frames to S-EL1.
			 
  * S-EL1 [OP-TEE      ] AES-GCM encryption of the APDU with the SCP03 session keys.
                         Sends the APDU request to EL1.
			 
  * EL1   [Linux kernel] Transmit the APDU to the I2C bus and receives a response
                         from the I2C secure element device (NXP SE05X).
			 Forwards the response to S-EL1.
			 
  * S-EL1 [OP-TEE      ] AES-GCM decryption and authentication of the response.
                         Sends the data to EL0.
			 
  * EL0   [User process] Processes the response

 -- Requirements:
 
    1) OP-TEE configures APDU PTA and NXP SE05x cryptographic driver.
    2) Linux kernel enables I2C support
       
Examples of usage::

  * Import NXP SE051 Certficate with the id 0xf0000123 into pkcs#11
    import-pkcs11 --import 0xf0000123 --id 45 --pin 87654321

  * Show NXP SE050 Certficate with the id 0xf0000123 on the console
    import-pkcs11 --show 0xf0000123 --se050

Use the optional --se050 if the device is an SE050

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
