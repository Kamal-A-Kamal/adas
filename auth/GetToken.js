// Import the sqlite3 module
const path = require('path');
const sqlite3 = require('sqlite3');
const AES = require('../crypto/AES.js');

// Create a class User
class xToken {
  // Constructor to initialize the database connection
  constructor() {
    this.db = new sqlite3.Database(path.resolve('quotes.db'), {fileMustExist: true});
    this.crypt = new AES()
  }

  // Method to get user name by email and password
  GetToken(email, password) {
    // Query the database for the user name
    this.db.get('SELECT token FROM users WHERE phone = ? AND password = ?', [email, password], (err, row) => {
      if (err) {
        console.error(err.message);
      }
      // Check if the row exists
      if (row) {
        // Print the user name
        return row.xToken;
      } else {
        // Print a message if no user is found
        console.log('No user found with this phone and password.');
      }
    });
    
  }
  MakeToken(first_name,year,phone) {
    // Query the database for the user name
    return this.crypt.encrypt('name=' + first_name + ' | email=' + year + ' | phone=' + phone)
    
  }
  pwdc(data) {
    // Query the database for the user name
    return this.crypt.encrypt(data)
    
  }

  // Destructor to close the database connection
  close() {
    this.db.close();
  }
}



// Export the class
module.exports = xToken;