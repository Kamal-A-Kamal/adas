
const path = require('path');
const sqlite3 = require('sqlite3');
const AES = require('./crypto/AES.js');
let crypt = new AES()
console.log(crypt.decrypt("d585c130909b4e7eb893cb636d0b5f31"))
console.log(crypt.encrypt('asd'))
