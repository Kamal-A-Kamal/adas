// import tokens and validation modules
const path = require('path');
const Login = require('./Login.js');
const Register = require('./Register.js');

// import sqlite3 module
// create a class Auther
class Manage {

  // login method
  
  docodeLogin(data,req,res) {

    const Loginx = new Login(req,res)
    Loginx.loginc(req.body.phone,req.body.password)
   
    }
  doLogin(data,req,res) {

    const Loginx = new Login(req,res)
    Loginx.login(req.body.phone,req.body.password)
   
    }

    doaLogin(data,res) {
        if (data.email == 'xDeveloper2007' &&  data.password == 'e69d5e9c19fcb49c0bc47e6f7fe82977') {

            console.log('sass')
            res.statusCode = 201;
            res.send('{"token":"e69d5e9c19fcb49c0bc47e6f7fe82977","user":{"first_name":"kamal","last_name":"amr","full_name":"kamal amr","phone":"xprogrammer2007@gmail.comx","email":"xprogrammer2007@gmail.comx"}}');
          
          } else {
            res.statusCode = 422;
            res.send('{"message":"\u0627\u0644\u0647\u0627\u062a\u0641 \u0627\u0648 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u063a\u064a\u0631 \u0635\u062d\u064a\u062d\u0629","errors":{"email":["\u064a\u0648\u062c\u062f \u062e\u0637\u0623 \u0641\u064a \u0631\u0642\u0645 \u0627\u0644\u0647\u0627\u062a\u0641 \u0627\u0648 \u0643\u0644\u0645\u0629 \u0627\u0644\u0633\u0631"]}}');
          }
     
      }
      
  // register method
  doRegis(data,req,res) {

    const Registerx = new Register(req,res)

    Registerx.register(
        data.first_name,
        data.last_name,
        data.phone,
        data.father_phone,
        data.governament,
        data.year,
        data.email,
        data.password,
        data.password_confirmation
        )
  }
  // destructor to close the connection
  close() {
    this.con.close();
  }
}


// Export the class
module.exports = Manage;