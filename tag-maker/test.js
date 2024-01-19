const {NFC, NFCReader, NFC_PROPERTY} = require('libnfc-js');
const { ReadData, ISOReadBinary, ISOSelectFile, AuthenticatePart1First } = require('./ntag424-commands');


let nfcReader = new NFCReader();
nfcReader.open();
console.log("Connected");
// nfcReader.setProperty(NFC_PROPERTY.NP_FORCE_ISO14443_A, true);
nfcReader.setProperty(NFC_PROPERTY.NP_FORCE_ISO14443_B, false);
nfcReader.setProperty(NFC_PROPERTY.NP_AUTO_ISO14443_4, true);
nfcReader.poll(async (card) => {
    try {
            
        console.log("CARD!", card);
        
        const doCommand = async (commandIterator) => {
            let result;
            let done = false;
        
            while (!done) {
                const cmdResult = commandIterator.next(result);
                done = cmdResult.done;
                
                if (!done) {
                    const cmd = cmdResult.value;
                    console.log("Sending ", cmd.toString('hex'));
                    const response = await nfcReader.transceive(cmd);
                    console.log("Response ", response.toString('hex'));
                    result = response;
                }
            }
        
            // Returns the result of the last command or undefined if no commands were executed
            return result;
        }
        
        const readNDef = async () => {

            await doCommand(
                ISOSelectFile(Buffer.from([0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]), 0x04)
            );

            await doCommand(
                ISOSelectFile(0xE104, 0x00)
            );

            // 00 b0 80 00 ff
            const [,ndefMessage] = await doCommand(
                // Length > 0xF8 - results in strange behavior?
                // At least in my configure, Le must be > 0, because somewhere between the PDC and libnfc, the length is causing the response to be truncated
                ISOReadBinary(0, 0, 248)
            );

            console.log(ndefMessage.toString());
        }
        await doCommand(
            ISOSelectFile(Buffer.from([0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]), 0x04)
        );
        
        const PiccChallenge = await doCommand(AuthenticatePart1First(0, Buffer.alloc(16)));

        console.log("PiccChallenge? ", PiccChallenge)
        
    } catch (e) {
        console.log("Error caught! ", e);
    } finally {

        await nfcReader.release();
        console.log('card released');
    }
});

// triggered if polling has failed
nfcReader.on('error', err => {
    console.log("ERROR CAUGHT ", err.message);
    process.exit();
})