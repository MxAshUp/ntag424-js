const crypto = require('crypto');

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