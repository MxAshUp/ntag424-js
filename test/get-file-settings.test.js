const { GetFileSettings, ACCESS_COND, ACCESS_SYMB, COMM_MODES } = require('../libs/ntag424-commands');

test('GetVersion from example', () => {
    
    const mockFileNo = 0x02;
    const commandIterator = GetFileSettings(mockFileNo);

    expect(commandIterator.next().value.toString('hex').toUpperCase()).toEqual(
        // Initial command to expect back
       '90F50000010200',
    );

    const finalResult = commandIterator.next(
        // Mock final response form PICC
        Buffer.from('0040e0ee000100c1f0001800003b00003b00009100', 'hex')
    ).value;
    expect(finalResult).toMatchObject({
        CommMode: COMM_MODES.PLAIN,
        FileSize: 256,
        FileType: 0,
        SDMMACInputOffset: 59,
        SDMMACOffset: 59,
        SDMMEnabled: true,
        SDMOptions: {
          EncodingMode: 'ASCII',
          SDMENCFileData: false,
          SDMReadCtr: true,
          SDMReadCtrLimit: false,
          UID: true,
        },
        SDMPICCDataOffset: 24,
        AccessRights: {
            [ACCESS_COND.READ]: ACCESS_SYMB.FREE_ACCESS,
            [ACCESS_COND.WRITE]: ACCESS_SYMB.FREE_ACCESS,
            [ACCESS_COND.READWRITE]: ACCESS_SYMB.FREE_ACCESS,
            [ACCESS_COND.CHANGE]: ACCESS_SYMB.KEY_0,
        },
        SDMAccessRights: {
            [ACCESS_COND.RFU]: ACCESS_SYMB.RFU,
            [ACCESS_COND.SDM_CTRRET]: ACCESS_SYMB.KEY_0,
            [ACCESS_COND.SDMFILE_READ]: ACCESS_SYMB.KEY_0,
            [ACCESS_COND.SDMMETA_READ]: ACCESS_SYMB.KEY_0,
        }
    });

});
