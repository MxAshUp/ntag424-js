# NTAG424 Node.js Utilities

## About

`ntag424-js` is currently under development. This library is designed to make it easy for developers to interact with NXP's NTAG 424 DNA products and to simplify the process personalizing tags and verifying/decrypting SUN data.

## Why use this library?

- Useful for creating a backend web server for NXP's NTAG 424 DNA.
- Useful for a tag personalization utility (setting encryption keys, NDEF mirroring, etc).
- Provides functions for parsing NDEF messages into PICCData and CMAC, etc.
- Decrypts PICCData into UID and NFC Counter.
- Verifies CMAC against a known private AES key.

## Library Overview

### Key Features

- **NTAG424 Communication/APDU Abstraction**: Provide your own NFC interface, and this library will construct commands, parse responses, check for errors and parameter validation.
- **NDEF Message Parsing**: Parse NDEF messages and extract the relevant data, such as PICCData and CMAC.
- **PICCData Decryption**: Decrypt PICCData to obtain UID and NFC Counter.
- **CMAC Verification**: Verify the CMAC using a known private AES key.
- (Future TODO) **Tag Tamper Status**: Decrypt tag tamper status.

## Commands to Implement
  - File Management
    - [ ] ChangeFileSettings
    - [ ] GetFileCounters
    - [x] GetFileSettings
  - Memory and Configuration
    - [ ] SetConfiguration
    - [!] GetCardUID
    - [ ] ReadSig
  - Data Management
    - [ ] ReadData
    - [ ] WriteData
  - Key Management
    - [ ] ChangeKey
    - [ ] GetKeyVersion
  - Authentication
    - [x] AuthenticatePart1First
    - [x] AuthenticatePart2
    - [ ] AuthenticatePart1NonFirst
    - [ ] LRP
  - ISO
    - [x] ISOReadBinary
    - [ ] ISOUpdateBinary
    - [x] ISOSelectFile
  - Misc
    - [x] GetVersion

## Example Usage

```javascript
const ntag424js = require('ntag424-js');

// ...
```

## Other Similar Libraries

Below is a list of other similar libraries for working with NXP's NTAG 424 DNA:

1. [node-sdm](https://www.npmjs.com/package/node-sdm): Simple library that includes CMAC verification and PICC decryption. 

1. [ntag424-tt-dna-node](https://www.npmjs.com/package/ntag424-tt-dna-node): Comprehensive typescript library for SDM and SSM. No documentation or source. Empty page on author's git: https://github.com/0xCold/ntag424-dna-tt-node


## libnfc-js Notes
Current status of libnfc-js
 - Limited to working with node 10.
 ( https://github.com/jimmythesaint82/libnfc-js/commit/4a820a786ae5102db4f65c7e720adf70ccb8fc81 )
 - WIP on Node 18 version
  - Has some memory issues

## NDEF Data type prefix notes
Some notes about byte prefixes I've seen associated with different NDEF data types

URL (SUN)
00 49 d1 01

URL
00 19 d1 01

Plain Text
00 11 d1 01
02 65 6E 79 6F - yo
02 65 6E E2 9D A4 EF B8 8F - ❤️
02 65 6E F0 9F A5 BA - 🥺

SMS
00 26 d1 01
// sms:5555555555?body=message test

Launch app
00 1d d4 0f

wifi
00 54 da 17

## libnfc Notes
libnfc config?

--- /etc/nfc/libnfc.conf	2023-03-31 14:34:37.731175399 -0700
+++ /etc/nfc/libnfc.conf.dpkg-new	2020-08-16 03:11:21.000000000 -0700
@@ -18,12 +18,3 @@
 # Note: if autoscan is enabled, default device will be the first device available in device list.
 #device.name = "microBuilder.eu"
 #device.connstring = "pn532_uart:/dev/ttyUSB0"
-#
-
-allow_autoscan = true
-allow_intrusive_scan = false
-log_level = 1
-#device.name = "ACR122"
-#device.connstring = "acr122_usb:001:011" # Use the bus number (001) and device address (011) from your lsusb output
-

acr122_usb:001:013