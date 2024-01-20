const crypto = require('crypto');
const aesCmac = require('node-aes-cmac').aesCmac;

module.exports.calculateMAC = (key, valueToMAC, truncate = false) => {
    const fullMAC = aesCmac(key, valueToMAC, { returnAsBuffer: true });

    if(!truncate) return fullMAC
    // Truncated to 8 bytes, using S14 || S12 || S10 || S8 || S6 || S4 || S2 || S0.
    // Even-numbered bytes shall be retained in MSB first order.  
    const truncatedMac = fullMAC.filter((_, i) => i % 2 !== 0);

    return truncatedMac;
}

module.exports.decryptAES = (key, data) => {
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, Buffer.alloc(16));
    decipher.setAutoPadding(false);

    return Buffer.concat([
        decipher.update(data),
        decipher.final(),
    ]);
}

module.exports.encryptAES = (key, data) => {
    const decipher = crypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(16));
    decipher.setAutoPadding(false);

    return Buffer.concat([
        decipher.update(data),
        decipher.final(),
    ]);
}