const { GetVersion } = require('../libs/ntag424-commands');

test('GetVersion from example', () => {
    
    const commandIterator = GetVersion();

    expect(commandIterator.next().value.toString('hex').toUpperCase()).toEqual(
        // Initial command to expect back
       '9060000000',
    );

    expect(commandIterator.next(
        // Send mock PICC back
        // Example shows 08 for sub type here, but that's invalid and maybe a typo? Corrected there to 02.
        Buffer.from('0404023000110591AF', 'hex')
    ).value.toString('hex').toUpperCase()).toEqual(
        // Encrypted challenge
        '90AF000000',
    );

    expect(commandIterator.next(
        // Send mock PICC back
        Buffer.from('0404020101110591AF', 'hex')
    ).value.toString('hex').toUpperCase()).toEqual(
        // Encrypted challenge
        '90AF000000',
    );

    const finalResult = commandIterator.next(
        // Mock final response form PICC
        Buffer.from('04968CAA5C5E80CD65935D4021189100', 'hex')
    ).value;

    expect(finalResult).toEqual({
        HWVendorID: 4,
        HWType: 4,
        HWSubType: 2,
        HWMajorVersion: 48,
        HWMinorVersion: 0,
        HWStorageSize: 17,
        HWProtocol: 5,
        HWSubType50pF: true,
        HWSubTypeStrongBackMod: true,
        HWSubTypeStandardBackMod: false,
        SWVendorID: 4,
        SWType: 4,
        SWSubType: 2,
        SWMajorVersion: 1,
        SWMinorVersion: 1,
        SWStorageSize: 17,
        SWProtocol: 5,
        UID: '04968CAA5C5E80',
        BathNo: 'CD65935D',
        CalendarWeekProduction: 21,
        YearProduction: 18,
        FabKeyID: undefined,
    });

});
