

const express = require("express")
const bodyParser = require("body-parser")
var cors = require('cors')
const sqlite3 = require('sqlite3');
const validator = require("email-validator");

const db = new sqlite3.Database('quotes.db');


var whitelist = ['http://localhost:3000', 'https://localhost:3000', ]
var corsOptions = {
  credentials: true,
  origin: function(origin, callback) {
    if (whitelist.indexOf(origin) !== -1) {
      callback(null, true)
    } else {
      callback(new Error('Not allowed by COR'))
    }
  }
}



app.use(bodyParser.json())
//app.use(bodyParser.urlencoded({ extended: true }));


app.use(cors({credentials: true, origin: 'http://localhost:3000'}));
app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", 'http://localhost:3000');
    res.header("Access-Control-Allow-Credentials", true);
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header("Access-Control-Allow-Headers", 'Origin,X-Requested-With,Content-Type,Accept,content-type,application/json');
    next();
});


// A middleware function that checks if an email exists in the database
function Data_validation(req, res, next) {
  
    // Get the email and phone from the request body
    const email = req.body.email;
    const phone = req.body.phone;
    const password = req.body.password
    const password_confirmation = req.body.password_confirmation
    const aa = '{"message": "The given data was invalid.", "errors": {}}';
    req.derrors = JSON.parse(aa);
   
 
     if (!validator.validate(email)) {
       req.derrors["errors"]["email"] = ['\u0644\u0627\u0632\u0645\u0020\u0627\u0644\u0628\u0631\u064a\u062f\u0020\u0627\u0644\u0625\u0644\u0643\u062a\u0631\u0648\u0646\u064a\u0020\u064a\u0628\u0642\u0627\u0020\u0635\u062d\u064a\u062d'];
     }
     if (password_confirmation != password) {
       req.derrors["errors"]["password"] = ['\u0020\u064a\u0631\u062c\u0649\u0020\u0627\u0644\u062a\u0623\u0643\u062f\u0020\u0643\u062a\u0627\u0628\u0629\u0020\u062a\u0623\u0643\u064a\u062f\u0020\u0643\u0644\u0645\u0629\u0020\u0627\u0644\u0633\u0631\u0020\u0628\u0646\u062c\u0627\u062d'];
     }
    // Query the database to find the user with that email or phone
    db.get('SELECT * FROM users WHERE email = ? OR phone = ?', [email, phone], (err, row) => {
      // Handle any errors
      if (err) {
        return next(err);
      }
  
      // If the user exists, send a 409 response and a message
      if (row) {
       res.status
       req.derrors["errors"]["email"] = ['\u0627\u0644\u0627\u064a\u0645\u064a\u0644\u0020\u0627\u0648\u0020\u0631\u0642\u0645\u0020\u0627\u0644\u0647\u0627\u062a\u0641\u0020\u0645\u0633\u062a\u062e\u062f\u0645'];
       req.derrors["errors"]["phone"] = ['\u0627\u0644\u0627\u064a\u0645\u064a\u0644\u0020\u0627\u0648\u0020\u0631\u0642\u0645\u0020\u0627\u0644\u0647\u0627\u062a\u0641\u0020\u0645\u0633\u062a\u062e\u062f\u0645'];
       
      }
      
      if (req.derrors["errors"]["email"] || req.derrors["errors"]["password"] || req.derrors["errors"]["phone"]){
       res.statusCode = 422;
       req.msg = JSON.stringify(req.derrors).replace(/\\\\/g,'\\')
      }else{
       const Auth = new Manage();
       Auth.doRegis(req.body,res)
      }
      // Otherwise, proceed to the next middleware or route handler
      next();
    });
    
    
 
 }
app.post("/api/auth/register", Data_validation, (req, res) =>  {
  
    //res.send(JSON.stringify(req.derrors).replace(/\\\\/g,'\\'))
    res.send(req.msg)
    // Get the user data from the request body
  
  })

  module.exports=a pp