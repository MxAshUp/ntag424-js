# NTAG424 DNA SUN Decrypt

## About

`ntag424-sun-utils` is a Node.js library that assists in verifying Message Authentication Code (MAC), decrypting Secure Unique NFC message (SUN), and parsing NDEF messages on NXP's NTAG 424 DNA (and eventually NTAG 424 DNA TagTamper). This library is designed to make it easy for developers to interact with NXP's NTAG 424 DNA products and to simplify the process of decrypting and verifying messages.

## Why use this library?

- Useful for creating a backend web server for NXP's NTAG 424 DNA.
- Provides functions for parsing NDEF messages into PICCData and CMAC.
- Decrypts PICCData into UID and NFC Counter.
- Verifies CMAC against a known private AES key.

## Library Overview

### Key Features

- **NDEF Message Parsing**: Parse NDEF messages and extract the relevant data, such as PICCData and CMAC.
- **PICCData Decryption**: Decrypt PICCData to obtain UID and NFC Counter.
- **CMAC Verification**: Verify the CMAC using a known private AES key.
- (Future TODO) **Secure Standard Messaging (SSM)**: Generates messages to be sent to NTAG 424, and parses responses. (SSM is used when programming the NTAG 424, changing keys, and custom applications)
- (Future TODO) **Tag Tamper Status**: Decrypt tag tamper status.


## Example Usage

```javascript
const ntag424SunUtils = require('ntag424-sun-utils');

// ...
```

## Other Similar Libraries

Below is a list of other similar libraries for working with NXP's NTAG 424 DNA:

1. [node-sdm](https://www.npmjs.com/package/node-sdm): Simple library that includes CMAC verification and PICC decryption. 

1. [ntag424-tt-dna-node](https://www.npmjs.com/package/ntag424-tt-dna-node): Comprehensive typescript library for SDM and SSM. No documentation or source. Empty page on author's git: https://github.com/0xCold/ntag424-dna-tt-node