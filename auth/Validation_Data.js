// import sqlite3 module
const path = require('path');
const sqlite3 = require('sqlite3');
var validator = require("email-validator");
const axios = require ('axios');

// define a class called ver
class CheckIt {
  // constructor to initialize the connection
  constructor(res) {
    this.resp = res
    this.db = new sqlite3.Database(path.resolve('quotes.db'), {fileMustExist: true});
  }



  // validate user data method
  validate(first_name, last_name, phone, father_phone, governament, year, email, password,password_confirmation) {
    const aa = '{"message": "The given data was invalid.", "errors": {}}';
    // initialize an empty object to store validation errors
    this.errors = JSON.parse(aa);
    // check if email is empty or not a valid email address
    if (!validator.validate(email)) {
      this.errors["errors"]["email"] = ['\u0644\u0627\u0632\u0645\u0020\u0627\u0644\u0628\u0631\u064a\u062f\u0020\u0627\u0644\u0625\u0644\u0643\u062a\u0631\u0648\u0646\u064a\u0020\u064a\u0628\u0642\u0627\u0020\u0635\u062d\u064a\u062d'];
    }
    /* else if (this.checkEmail(email)) {
      this.errors["errors"]["email"] = ['\u0627\u0644\u0627\u064a\u0645\u064a\u0644\u0020\u0645\u0633\u062a\u062e\u062f\u0645\u0020\u0628\u0627\u0644\u0641\u0639\u0644'];
    }
*//*

    // check if phone exists in the database
    if (this.checkPhone(phone)) {
        this.errors["errors"]["phone"] = ['\u0627\u0644\u0631\u0642\u0645\u0020\u0645\u0633\u062a\u062e\u062f\u0645\u0020\u0628\u0627\u0644\u0641\u0639\u0644'];
    }
*/

    if (password_confirmation != password) {
        this.errors["errors"]["password"] = ['\u0020\u064a\u0631\u062c\u0649\u0020\u0627\u0644\u062a\u0623\u0643\u062f\u0020\u0643\u062a\u0627\u0628\u0629\u0020\u062a\u0623\u0643\u064a\u062f\u0020\u0643\u0644\u0645\u0629\u0020\u0627\u0644\u0633\u0631\u0020\u0628\u0646\u062c\u0627\u062d'];
    }

      // return true if no errors, false otherwise
      if ((!this.errors["errors"]["phone"]) && (!this.errors["errors"]["father_phone"]) && (!this.errors["errors"]["email"]) && (!this.errors["errors"]["password"])) {
          return 'tr';
      } else {
        // return validation errors
          return JSON.stringify(this.errors).replace(/\\\\/g,'\\');
        }
  }
  // close the database connection
  close() {
    this.db.close((err) => {
      if (err) {
        throw err;
      }
    });
  }
}  module.exports = CheckIt;

