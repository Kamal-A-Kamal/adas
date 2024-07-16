// import tokens and validation modules
// import sqlite3 module
const sqlite3 = require('sqlite3');
const path = require('path');
const xToken = require('./GetToken.js');
// create a class Auther
class Login {
  // constructor to initialize the connection
  constructor(req,res) {
    this.reqe = req
    this.resp = res
    this.con = new sqlite3.Database(path.resolve('quotes.db'), {fileMustExist: true});
    this.crypt = new xToken();
  }

  // login method
  login(phone, password) {
    const dx = this.crypt.pwdc(password);
    
    // validate the phone format
    const query = `SELECT * FROM users WHERE (email = '${phone}' OR phone = '${phone}') AND (password = "${dx}")`;
    // fetching data from database
    console.log(query)
    this.con.get(query, (err, row) => {
      if (err) {
        throw err;
      }
      if (row) {
        const sql = "INSERT INTO d_info (phone, type, operator, browser, op) VALUES (?, ?, ?, ?, ?)";
        this.con.get(sql, [row["phone"], this.reqe.xtype, this.reqe.os, this.reqe.xbrowser, 'login'], (err) => {
          if (err) {
            throw err;
          }
        });

        this.resp.statusCode = 201;
        this.resp.send('{"token":"'+row["token"]+'","user":{"first_name":"' + row["first_name"] + '","last_name":"' + row["last_name"] + '","full_name":"' + row["first_name"] + ' ' + row["last_name"] + '","year":"' + row["year"] + '","phone":' + row["phone"] + ',"email":"' + row["email"] + '"}}');
      } else {
        this.resp.statusCode = 422;
        this.resp.send('{"message":"\u0627\u0644\u0647\u0627\u062a\u0641 \u0627\u0648 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u063a\u064a\u0631 \u0635\u062d\u064a\u062d\u0629","errors":{"phone":["\u064a\u0648\u062c\u062f \u062e\u0637\u0623 \u0641\u064a \u0631\u0642\u0645 \u0627\u0644\u0647\u0627\u062a\u0641 \u0627\u0648 \u0643\u0644\u0645\u0629 \u0627\u0644\u0633\u0631"]}}');

      }
    });
  }
  loginc(phone, password) {
    const dx = password;
    
    // validate the phone format
    const query = `SELECT * FROM insert_autos WHERE (code = "${dx}")`;
    // fetching data from database
    console.log(query)
    this.con.get(query, (err, row) => {
      if (err) {
        throw err;
      }
      if (row) {

        this.resp.statusCode = 201;
        this.resp.send('{"token":"'+dx+'","user":{"first_name":"' + row["title"] + '","last_name":"' + "x" + '","full_name":"' + row["title"] + ' x' +'","year":"' + "1" + '","phone":' + dx + ',"email":"' + dx + '"}}');
      } else {
        
        this.resp.statusCode = 422;
        this.resp.send('{"message":"الكود غير صحيح","errors":{"phone":["\u064a\u0648\u062c\u062f \u062e\u0637\u0623 \u0641\u064a \u0631\u0642\u0645 \u0627\u0644\u0647\u0627\u062a\u0641 \u0627\u0648 \u0643\u0644\u0645\u0629 \u0627\u0644\u0633\u0631"]}}');

      }
    });
  }
  // destructor to close the connection
  close() {
    this.con.close();
  }
}


// Export the class
module.exports = Login;