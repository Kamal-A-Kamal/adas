// Import the crypto module
const crypto = require('crypto');

// Define the class
class AES {
  // Constructor takes the private key as a parameter
  constructor() {
    // Set the private key as a property
    this.privateKey = 'wedadmasryakhawal';
  }

  // Method to encrypt a text
  encrypt(text) {
    // Create an aes-256-cbc cipher with the private key
    const cipher = crypto.createCipher('aes-256-cbc', this.privateKey);
    // Encrypt the text and return it as a hex string
    return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
  }

  // Method to decrypt a hex string
  decrypt(hex) {
    // Create an aes-256-cbc decipher with the private key
    const decipher = crypto.createDecipher('aes-256-cbc', this.privateKey);
    // Decrypt the hex string and return it as a utf8 string
    return decipher.update(hex, 'hex', 'utf8') + decipher.final('utf8');
  }
  
 ien(text, key) {
  let encryptedInteger = 0;
  for (let i = 0; i < text.length; i++) {
    encryptedInteger ^= text.charCodeAt(i) << (i % 4 * 8);
  }
  return encryptedInteger;
}

// Function to decrypt an integer back into text
 idec(encryptedInteger, key) {
  let decryptedText = '';
  for (let i = 0; i < 4; i++) {
    decryptedText += String.fromCharCode((encryptedInteger >> (i * 8)) & 0xff);
  }
  return decryptedText;
}
  
}

// Export the class
module.exports = AES;
