const { decryptAES, encryptAES, calculateMAC } = require("./utils");
const crypto = require('crypto');

// Enum for other constants
const CLA_MFG = 0x90;
const CLA_ISO = 0x00;

const SINGLE_EMPTY = Buffer.from([0x00]);
const CMDS = {
    // CLA = 0x90
    SetConfiguration:          0x5C,

    ChangeFileSettings:        0x5F,
    ChangeKey:                 0xC4,
    GetFileCounters:           0xF6,
    GetFileSettings:           0xF5,
    GetKeyVersion:             0x64,

    GetCardUID:                0x51,
    ReadSig:                   0x3C,
    GetVersion:                0x60,

    ReadData:                  0xAD,
    WriteData:                 0x8D,

    AuthenticatePart1First:    0x71,
    AuthenticatePart1NonFirst: 0x77,
    AuthenticatePart2:         0xAF,

    // CLA = 0x00
    ISOReadBinary:             0xB0,
    ISOUpdateBinary:           0xD6,
    ISOSelectFile:             0xA4,
};

module.exports.ISOIDs = {
    PiccMFName: Buffer.from('D2760000850101', 'hex'),
    PiccMFID: 0x3F00,
    AppDFName: Buffer.from('D2760000850101', 'hex'),
    AppDFID: 0xE110,
}

const STATUS_SYMB = {
    OPERATION_OK:           Symbol('OPERATION_OK'),
    ILLEGAL_COMMAND_CODE:   Symbol('ILLEGAL_COMMAND_CODE'),
    INTEGRITY_ERROR:        Symbol('INTEGRITY_ERROR'),
    NO_SUCH_KEY:            Symbol('NO_SUCH_KEY'),
    LENGTH_ERROR:           Symbol('LENGTH_ERROR'),
    PERMISSION_DENIED:      Symbol('PERMISSION_DENIED'),
    PARAMETER_ERROR:        Symbol('PARAMETER_ERROR'),
    AUTHENTICATION_DELAY:   Symbol('AUTHENTICATION_DELAY'),
    AUTHENTICATION_ERROR:   Symbol('AUTHENTICATION_ERROR'),
    ADDITIONAL_FRAME:       Symbol('ADDITIONAL_FRAME'),
    BOUNDARY_ERROR:         Symbol('BOUNDARY_ERROR'),
    COMMAND_ABORTED:        Symbol('COMMAND_ABORTED'),
    FILE_NOT_FOUND:         Symbol('FILE_NOT_FOUND'),
    MEMORY_ERROR:           Symbol('MEMORY_ERROR'),
    WRONG_LENGTH:           Symbol('WRONG_LENGTH'),
    SEC_STATUS_UNSATISFIED: Symbol('SEC_STATUS_UNSATISFIED'),
    COND_USE_NOT_SATISFIED: Symbol('COND_USE_NOT_SATISFIED'),
    INCORRECT_CMD_PARAMS:   Symbol('INCORRECT_CMD_PARAMS'),
    FILE_NOT_FOUND:         Symbol('FILE_NOT_FOUND'),
    INCORRECT_PARAMS_P1P2:  Symbol('INCORRECT_PARAMS_P1P2'),
    LC_INCONSISTENT_P1P2:   Symbol('LC_INCONSISTENT_P1P2'),
    WRONG_LE_FIELD:         Symbol('WRONG_LE_FIELD'),
    INVALID_INSTRUCTION:    Symbol('INVALID_INSTRUCTION'),
    CLASS_NOT_SUPPORTED:    Symbol('CLASS_NOT_SUPPORTED'),
}

const SW_LOOKUP = {
    [CLA_MFG]: {
        0x9100: STATUS_SYMB.OPERATION_OK,
        0x911C: STATUS_SYMB.ILLEGAL_COMMAND_CODE,
        0x911E: STATUS_SYMB.INTEGRITY_ERROR,
        0x9140: STATUS_SYMB.NO_SUCH_KEY,
        0x917E: STATUS_SYMB.LENGTH_ERROR,
        0x919D: STATUS_SYMB.PERMISSION_DENIED,
        0x919E: STATUS_SYMB.PARAMETER_ERROR,
        0x91AD: STATUS_SYMB.AUTHENTICATION_DELAY,
        0x91AE: STATUS_SYMB.AUTHENTICATION_ERROR,
        0x91AF: STATUS_SYMB.ADDITIONAL_FRAME,
        0x91BE: STATUS_SYMB.BOUNDARY_ERROR,
        0x91CA: STATUS_SYMB.COMMAND_ABORTED,
        0x91EE: STATUS_SYMB.MEMORY_ERROR,
        0x91F0: STATUS_SYMB.FILE_NOT_FOUND,
    },
    [CLA_ISO]: {
        0x9000: STATUS_SYMB.OPERATION_OK,
        0x6700: STATUS_SYMB.WRONG_LENGTH,
        0x6982: STATUS_SYMB.SEC_STATUS_UNSATISFIED,

        0x6985: STATUS_SYMB.COND_USE_NOT_SATISFIED,
        // Wrapped chained command or multiple pass command ongoing.
        // No file selected.
        // Targeted file is not of StandardData.
        // Application of targeted file holds a TransactionMAC file.

        0x6A80: STATUS_SYMB.INCORRECT_CMD_PARAMS,
        0x6A82: STATUS_SYMB.FILE_NOT_FOUND,
        0x6A86: STATUS_SYMB.INCORRECT_PARAMS_P1P2,
        0x6A87: STATUS_SYMB.LC_INCONSISTENT_P1P2,
        0x6C00: STATUS_SYMB.WRONG_LE_FIELD,
        0x6D00: STATUS_SYMB.INVALID_INSTRUCTION,
        0x6E00: STATUS_SYMB.CLASS_NOT_SUPPORTED,
    }
}

const isUndefined = (val) => typeof val === 'undefined';

const isDefined = (val) => typeof val !== 'undefined';

const intBufferBE = (intValue, bufferSize) => {
    const buffer = Buffer.alloc(bufferSize);
    for (let i = 0; i < bufferSize; i++) {
        // Extract each byte from the integer and assign it to the buffer
        buffer[bufferSize - 1 - i] = (intValue >> (8 * i)) & 0xFF;
    }
    return buffer;
}

const intBufferLE = (intValue, bufferSize) => {
    const buffer = Buffer.alloc(bufferSize);
    for (let i = 0; i < bufferSize; i++) {
        // Extract each byte from the integer and assign it to the buffer in little-endian order
        buffer[i] = (intValue >> (8 * i)) & 0xFF;
    }
    return buffer;
}

const processResponse = (cla, resBuff, expectedStatuses = [STATUS_SYMB.OPERATION_OK]) => {
    // Then proceed to process response
    if(resBuff.length < 2) {
        // Something wacky going on here
        throw new Error(`Unexpected response length ${resBuff.length} bytes`);
    }
    // The last 2 bytes will be the status code, and everything prior will be the data
    const SW1 = resBuff[resBuff.length - 2];
    const SW2 = resBuff[resBuff.length - 1];
    const SWPAIR = (SW1 << 8) + SW2;
    const lookupCode = SW_LOOKUP[cla][SWPAIR];

    if(isUndefined(lookupCode) && SW1 == 0x6C && SW2 > 0x00) {
        lookupCode = STATUS_SYMB.WRONG_LE_FIELD;
    }

    if(!expectedStatuses.includes(lookupCode)) {
        if(isUndefined(lookupCode)) {
            throw new Error(`UNKNOWN_ERROR status words: ${SW1.toString(16)} ${SW2.toString(16)}`);
        }
        throw new Error(`Unexpected Word response: ${lookupCode.toString()}. Expected one of ${expectedStatuses.map(s => s.toString()).join(',')}. ${resBuff.toString('hex')}`);
    }

    // Return a just the data part of the buffer
    return [lookupCode, resBuff.subarray(0, resBuff.length - 2)];
}

// module.exports.ChangeFileSettings = (options = {}) => {
//     let {
//         fileNo, // 5 bits long
//         sDMEnabled, // bool
//         commMode, // Plain = X0b, MAC = 01b, Full = 11b
//         accessRights,
//         sDMOptions: {
//             UID, // Bool
//             SDMReadCtr, // Bool
//             SDMReadCtrLimit, // Bool
//             SDMENCFileData, // Bool
//         } = {},
//         SDMAccessRights: {
//             EncryptedPICCData, // Eh = Plain, Fh = No mirroring
//             SDMFileReadAccessRights,
//             SDMCtrRetAccessRights
//         } = {},
//         UIDOffset, // Mirror position (LSB first) for UID. (FileSize - UIDLength)
//     } = options;

//     const CMD = 0x5F;
//     return Buffer.from([
//         CLA_MFG,
//         CMDS.ChangeFileSettings,
//         P1,
//         P2,

//     ])
//     fileNo = options.fileNo & 0x1F; // 5 bits for FileNo

//     return fileNo.toString(16);
// }

// Note, leave MockRndA undefined, unless testing or providing different random buffer
// KeyNo must be 0-4
module.exports.AuthenticateEV2First = function* (KeyNo, KeyValue, MockRndA) {
    const RndB = yield* module.exports.AuthenticateEV2FirstPart1(KeyNo, KeyValue);
    const RndA = MockRndA || crypto.randomBytes(16);
    return yield* module.exports.AuthenticateEV2FirstPart2(KeyValue, RndB, RndA);
}

module.exports.AuthenticateEV2FirstPart1 = function* (KeyNo, KeyValue) {
    
    const pdCap = Buffer.from([
        // This can be up to 6 bytes, but docs say to keep it at 0x00
        // 0x00,
        // 0x00,
        // 0x00,
        // 0x00,
        // 0x00,
        // 0x00,
    ]);

    const data = Buffer.from([
        KeyNo & 0b00111111, // 7-6 RFU
        pdCap.length, // LendCap = 0
    ]);

    const Lc = data.length + pdCap.length;

    const header = Buffer.from([
        CLA_MFG,
        CMDS.AuthenticatePart1First,
        0x00,
        0x00,
        Lc,
    ]);

    const response = yield Buffer.concat([
        header,
        data,
        pdCap,
        SINGLE_EMPTY
    ]);

    const [,challenge] = processResponse(CLA_MFG, response, [STATUS_SYMB.ADDITIONAL_FRAME]);
    
    const RndB = decryptAES(KeyValue, challenge);

    return RndB;
}

module.exports.AuthenticateEV2FirstPart2 = function* (KeyValue, RndB, RndA) {

    // Rotate the buffer left by 1 byte
    const RndBi = Buffer.concat([RndB.subarray(1), RndB.subarray(0, 1)]);

    const EncryptedChallengeResponse = encryptAES(KeyValue, Buffer.concat([RndA, RndBi]));
    
    const part2CommandHeader = Buffer.from([
        CLA_MFG,
        CMDS.AuthenticatePart2,
        0x00,
        0x00,
        EncryptedChallengeResponse.length,
    ]);

    const secondResponse = yield Buffer.concat([
        part2CommandHeader,
        EncryptedChallengeResponse,
        SINGLE_EMPTY
    ]);

    const [,capabilitiesE] = processResponse(CLA_MFG, secondResponse);

    const capabilities = decryptAES(KeyValue, capabilitiesE);
    const TI = capabilities.subarray(0,4);
    const CheckRndA = capabilities.subarray(4,20);
    const PDcap2 = capabilities.subarray(20,26);
    const PCDcap2 = capabilities.subarray(26,32);
  
    // Check that CheckRndA is a rotated version of RndA
    const validRndA = CheckRndA.every((byte, index) => byte == RndA[(index + 1) % 16]);

    if(!validRndA) {
        throw new Error(`RndA check failed to match.`);
    }

    // SV1 Calculation
    // A5h||5Ah||00h||01h||00h||80h||
    // RndA[15..14]||
    // ( RndA[13..8] ^ RndB[15..10]) ||
    // RndB[9..0]||RndA[7..0]
    const SV1 = Buffer.concat([
        Buffer.from([
            0xA5,0x5A,0x00,0x01,0x00,0x80
        ]),
        RndA.subarray(0,2), // RndA[15:14]
        Buffer.from([
            // ( RndA[13..8] ^ RndB[15..10])
            RndA[2] ^ RndB[0],
            RndA[3] ^ RndB[1],
            RndA[4] ^ RndB[2],
            RndA[5] ^ RndB[3],
            RndA[6] ^ RndB[4],
            RndA[7] ^ RndB[5],
        ]),
        RndB.subarray(6,16), // RndB[9..0]
        RndA.subarray(8,16), // RndA[7..0]
    ]);

    // SV2 Calculation
    // 5Ah||A5h||00h||01h||00h||80h||
    // RndA[15..14]||
    // ( RndA[13..8] ^ RndB[15..10]) ||
    // RndB[9..0]||RndA[7..0]
    const SV2 = Buffer.concat([
        Buffer.from([
            0x5A,0xA5,0x00,0x01,0x00,0x80
        ]),
        RndA.subarray(0,2), // RndA[15:14]
        Buffer.from([
            // ( RndA[13..8] ^ RndB[15..10])
            RndA[2] ^ RndB[0],
            RndA[3] ^ RndB[1],
            RndA[4] ^ RndB[2],
            RndA[5] ^ RndB[3],
            RndA[6] ^ RndB[4],
            RndA[7] ^ RndB[5],
        ]),
        RndB.subarray(6,16), // RndB[9..0]
        RndA.subarray(8,16), // RndA[7..0]
    ]);
 
    // Enc Session Key = CMAC(K0, SV1)
    const EncryptionSessionKey = calculateMAC(KeyValue, SV1);
  
    // CMAC Session Key = CMAC(K0, SV2)
    const CMACSessionKey = calculateMAC(KeyValue, SV2);

    return {
        TI,
        PDcap2,
        PCDcap2,
        SV1,
        SV2,
        EncryptionSessionKey,
        CMACSessionKey,
    };
}

module.exports.ReadData = function* (FileNo, Offset = 0, Length = 0) {
    const data = Buffer.concat([
        intBufferLE(FileNo, 1),
        intBufferLE(Offset, 3),
        intBufferLE(Length, 3),
    ]);

    const Lc = data.length & 0xFF;

    const header = Buffer.from([
        CLA_MFG,
        CMDS.ReadData,
        0x00, // P1
        0x00, // P2
        Lc,
    ]);

    // Send command
    const response = yield Buffer.concat([header, data, SINGLE_EMPTY]);

    return processResponse(CLA_MFG, response);
}

module.exports.ISOReadBinary = function* (FileNo, Offset, Length) {

    let P1 = 0;
    let P2 = 0;
    let Le = 0;

    // FileNo = 0 means currently selected
    // TODO
    // FileNo must be between 0x01 and 0x1E

    if(isDefined(FileNo)) {
        // Encoding is set (bit 7 = 1) to include FileNo
        P1 |= 0b10000000;
        P1 |= (FileNo & 0x1F);
        if(isDefined(Offset)) {
            P2 = Offset & 0xFF;
        } else {
            P2 = 0;
        }
    } else {
        if(isDefined(Offset)) {
            P1 = Offset >> 8;
            P2 = Offset & 0xFF;
        } else {
            // No offset, no fileno, means we select default file 0
            P1 = 0b10000000;
            P2 = 0;
        }
    }

    if(Length) {
        Le = Length & 0xFF;
    }

    const header = Buffer.from([
        CLA_ISO,
        CMDS.ISOReadBinary,
        P1,
        P2,
        Le
    ]);

    // Send command
    const response = yield header;

    return processResponse(CLA_ISO, response);
}

// SelectionControl (SC)
//  0 - Select by file id (MF, DF or EF)
//  1 - Select child by file id (DF)
//  2 - Select child by file id (EF)
//  3 - Select parent DF
//  4 - Select by file name (DF)
// FileIdentifier must be an int (for 0,1,2 SC modes) or a buffer array (for SC mode 4).
module.exports.ISOSelectFile = function* (FileIdentifier, SelectionControl, ReturnFCITemplate) {
    
    let P1 = 0;
    let P2 = 0;
    let identifier;

    if(!isDefined(SelectionControl)) {
        throw new Error(`SelectionControl must be one of 0x00, 0x01, 0x03, 0x04`);
    }

    P1 = SelectionControl;
    if(SelectionControl == 0x03 && isDefined(FileIdentifier)) {
        throw new Error(`FileIdentifier cannot be used with 0x03 selection control.`);
    }
    if(SelectionControl >= 0x00 && SelectionControl <= 0x03 && isDefined(FileIdentifier)) {
        if(isDefined(FileIdentifier)) {
            // TODO - maybe allow FileIdentifier to be a buffer or an int? Currently just int allowed.
            identifier = intBufferBE(FileIdentifier, 2);
        }
    }
    if(SelectionControl == 0x04) {
        if(isUndefined(FileIdentifier)) {
            throw new Error(`FileIdentifier name must be included.`);
        }
        if(FileIdentifier.length > 16) {
            throw new Error(`FileIdentifier cannot be > 16 bytes`);
        }
        identifier = FileIdentifier;
    }

    P2 = 0x0C;
    if(ReturnFCITemplate) {
        P2 = 0;
    }

    // 00h - 10h
    const Lc = isDefined(identifier) ? identifier.length & 0xFF : 0;
    const data = isDefined(identifier) ? identifier : Buffer.from([]);

    const header = Buffer.from([
        CLA_ISO,
        CMDS.ISOSelectFile,
        P1,
        P2,
        Lc,
    ]);
    const command = Buffer.concat([
        header,
        data,
        SINGLE_EMPTY, // ? Should this be > 0 if ReturnFCITemplate = true
    ]);

    const response = yield command;

    return processResponse(CLA_ISO, response);
}

module.exports.WriteData = (FileNo, Data, Offset = 0) => {
    if(Data.length > 248) {
        throw new Error(`WriteData: Data buffer size must be <= 248`);
    }

    const data = Buffer.concat([
        intBufferLE(FileNo, 1),
        intBufferLE(Offset, 3),
        intBufferLE(Data.length, 3),
        Data,
    ]);

    const Lc = data.length & 0xFF;

    const header = Buffer.from([
        CLA_MFG,
        CMDS.WriteData,
        0x00, // P1
        0x00, // P2
        Lc,
    ]);

    return Buffer.concat([header, data, SINGLE_EMPTY]);
}