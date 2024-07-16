// Import the sqlite3 module
const sqlite3 = require('sqlite3');

// Create a database connection
let db = new sqlite3.Database(path.resolve('quotes.db'), {fileMustExist: true});
  

// Prepare an SQL statement to create the users table
const sql = `CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  token TEXT,
  first_name TEXT,
  last_name TEXT,
  phone TEXT,
  father_phone TEXT,
  governament TEXT,
  year INTEGER,
  email TEXT,
  password TEXT,
  time_account_created DATETIME DEFAULT (datetime('now', '+2 hours'))
)`;

// Execute the statement
db.run(sql, (err) => {
  if (err) {
    throw err;
  }
  console.log('Table created');
});

// Close the database connection
db.close();



CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  token TEXT,
  first_name TEXT,
  last_name TEXT,
  phone TEXT,
  father_phone TEXT,
  governament TEXT,
  year INTEGER,
  email TEXT,
  password TEXT,
  time_account_created DATETIME DEFAULT (datetime('now', '+2 hours'))
)



CREATE TABLE IF NOT EXISTS d_info (
  id INTEGER PRIMARY KEY,
  phone TEXT,
  type TEXT,
  operator TEXT,
  browser TEXT,
  op TEXT,
  time_account_created DATETIME DEFAULT (datetime('now', '+2 hours'))
)