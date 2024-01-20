const { AuthenticatePart1First } = require('../tag-maker/ntag424-commands');

test('AuthenticatePart1First', () => {
    // This test is a replication of the AuthenticateEV2First example in section 6.6 of AN12196.pdf
    const KeyNo = 0x00;
    const KeyValue = Buffer.alloc(16); //0x00000000000000000000000000000000;
    const MockRndA = Buffer.from('13C5DB8A5930439FC3DEF9A4C675360F', 'hex');
    const commandIterator = AuthenticatePart1First(KeyNo, KeyValue, MockRndA);

    expect(commandIterator.next().value.toString('hex').toUpperCase()).toEqual(
        // Initial command to expect back
       '9071000002000000',
    );

    expect(commandIterator.next(
        // Send mock PICC back
        Buffer.from('A04C124213C186F22399D33AC2A3021591AF', 'hex')
    ).value.toString('hex').toUpperCase()).toEqual(
        // Encrypted challenge
        '90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00',
    );

    const finalResult = commandIterator.next(
        // Mock final response form PICC
        Buffer.from('3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F081206639100', 'hex')
    ).value;

    expect(finalResult.TI.toString('hex').toUpperCase())                    .toEqual('9D00C4DF');
    expect(finalResult.PDcap2.toString('hex').toUpperCase())                .toEqual('000000000000');
    expect(finalResult.PCDcap2.toString('hex').toUpperCase())               .toEqual('000000000000');
    expect(finalResult.SV1.toString('hex').toUpperCase())                   .toEqual('A55A0001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F');
    expect(finalResult.SV2.toString('hex').toUpperCase())                   .toEqual('5AA50001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F');
    expect(finalResult.EncryptionSessionKey.toString('hex').toUpperCase())  .toEqual('1309C877509E5A215007FF0ED19CA564');
    expect(finalResult.CMACSessionKey.toString('hex').toUpperCase())        .toEqual('4C6626F5E72EA694202139295C7A7FC7');
});