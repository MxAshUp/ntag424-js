const { GetFileSettings } = require('../libs/ntag424-commands');

test('GetVersion from example', () => {
    
    const mockFileNo = 0x02;
    const commandIterator = GetFileSettings(mockFileNo);

    expect(commandIterator.next().value.toString('hex').toUpperCase()).toEqual(
        // Initial command to expect back
       '90F50000010200',
    );

    const finalResult = commandIterator.next(
        // Mock final response form PICC
        Buffer.from('004300E0000100C1F1212000004300009100', 'hex')
    ).value;

    expect(finalResult).toEqual({
    });

});
