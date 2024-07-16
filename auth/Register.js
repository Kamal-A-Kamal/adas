// import tokens and validation modules
const xToken = require('./GetToken.js');
const path = require('path');
// import sqlite3 module
const sqlite3 = require('sqlite3');

// create a class Auther
class Register {
  // constructor to initialize the connection
  constructor(req,res) {
    this.reqe = req
    this.resp = res
    this.crypt = new xToken();
    this.con = new sqlite3.Database(path.resolve('quotes.db'), {fileMustExist: true});
  }

  // login method

  // register method
  register(first_name, last_name, phone, father_phone, governament, year, email, password, password_confirmation) {
    // validate user data
   
      const token = this.crypt.MakeToken(first_name,year,phone);
      // prepare an SQL query
      const sql = "INSERT INTO users (token, first_name, last_name, phone, father_phone, governament, year, email, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

      // execute the query
      this.con.get(sql, [token,
        first_name,
        last_name,
        phone,
        father_phone,
        governament,
        year,
        email,
        this.crypt.pwdc(password)], (err) => {
          if (err) {
            throw err;
          } 
                
        })
        
        const sqlx = "INSERT INTO d_info (phone, type, operator, browser, op) VALUES (?, ?, ?, ?, ?)";
        this.con.get(sqlx, [phone, this.reqe.xtype, this.reqe.os, this.reqe.xbrowser, 'login'], (err) => {
          if (err) {
            throw err;
          }
        });

        this.resp.statusCode = 201;
        this.resp.send('{"token":"' +token+ '","user":{"first_name":"' + first_name + '","last_name":"' + last_name + '","full_name":"' + first_name + ' ' + last_name + '","year":' + year + ',"phone":' + phone + ',"email":"' + email + '"}}');
      ;
    

  }

  // destructor to close the connection
  close() {
    this.con.close();
  }
}

module.exports = Register;