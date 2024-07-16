const express = require("express")
var obj = require('./config.json');
const bodyParser = require("body-parser")
const Manage = require('./auth/AuthService.js')
var cors = require('cors')
const sqlite3 = require('sqlite3');
const path = require('path');
const validator = require("email-validator");
const db = new sqlite3.Database('quotes.db');
const AES = require("./crypto/AES.js")
const device = require('express-device');
var platform = require('platform');
const fileUpload = require("express-fileupload");
const axios = require('axios');
const { use } = require("express/lib/application");




const app = express()
const crypto = new AES
const PORT = 3030

const sqlRegex = /((%3D)|(=))[^\n]*((%27)|(\')|(\-\-)|(%3B)|(;)|(\/\*)|(\*)|(\|\|)|(%7C%7C)|(#))/i;

function hasSqlInjection(payload) {
  return sqlRegex.test(payload);
}

function checkSqlInjection(req, res, next) {
  // Check GET parameters for SQL injection
  for (let param in req.query) {
    if (hasSqlInjection(req.query[param])) {
      return res.status(400).json({ error: 'SQL injection detected in GET parameters' });
    }
  }

  // Check request parameters (params) for SQL injection
  for (let param in req.params) {
    if (hasSqlInjection(req.params[param])) {
      return res.status(400).json({ error: 'SQL injection detected in request parameters' });
    }
  }

  // Check POST request body for SQL injection
  for (let param in req.body) {
    if (typeof req.body[param] === 'string' && hasSqlInjection(req.body[param])) {
      return res.status(400).json({ error: 'SQL injection detected in request body' });
    }
  }

  // Check Authorization bearer token for SQL injection
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    if (token && hasSqlInjection(token)) {
      return res.status(400).json({ error: 'SQL injection detected in Authorization token' });
    }
  }

  // If no SQL injection is detected, proceed to the next middleware
  next();
}


//cors
//console.log(obj.cors)
//var whitelist = ['http://'+obj.cors, 'https://'+obj.cors, ]
//var corsOptions = {credentials: true,origin: function(origin, callback) {if (whitelist.indexOf(origin) !== -1) {callback(null, true)} else {callback(new Error('Not allowed by COR'))}}}

const allowedOrigins = ['http://localhost:3000', 'http://localhost:63235'];

const corsOptions = {
    origin: function (origin, callback) {
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
          callback(null, true);
        }
    },
    credentials: true  // if you need to support credentials (cookies, authorization headers, etc.)
};

app.use(cors(corsOptions));

app.use(bodyParser.json())
app.use(device.capture());
app.use(fileUpload());
app.use(function(req,res,next){let ua = req.headers['user-agent'];var info = platform.parse(ua);req.xbrowser = info.name;req.os = info.os.family;req.xtype = req.device.type;next()})
app.use(express.static(__dirname + '/pub'));
app.use(checkSqlInjection);


function restrictToAdmin(req, res, next) {
  // Assuming you have a way to determine the type of token from the request
  const authHeader = req.headers['authorization'];
  if(authHeader){
  const token = authHeader.split(' ')[1]; // Example: get the token from headers

  // Check if the token is an admin token
  if (token === "e69d5e9c19fcb49c0bc47e6f7fe82977") {
      // Token belongs to an admin, allow access
      next(); // Proceed to the next middleware or route handler
  } else {
      // Token does not belong to an admin, deny access
      res.status(403).json({ error: "Access forbidden. Admin privileges required." });
  }
}else{
  res.status('404').send('No-Routes')
}}

/*
app.use(express.static(path.resolve(__dirname, "courses_images")));
app.use("/courses_images", serveIndex(path.resolve(__dirname, "courses_images")));


*/

app.get("/api/fetch_global_notification" , (req,res) => {
  res.send('[]')
})




app.get("/api/user" , (req ,res )=> {
  const authHeader = req.headers['authorization'];
  if(authHeader){
  const token = authHeader.split(' ')[1]
  db.get(`SELECT * FROM users WHERE token = ?`, [token], (err, row) => {
    res.send(

      `{
        "user": {
            "first_name": "`+row["first_name"]+`",
            "last_name": "`+row["last_name"]+`",
            "full_name": "`+row["first_name"]+' '+row["last_name"]+`",
            "insert_auto_id": null,
            "insert_auto_code": null,
            "creation_method": "register",
            "insert_auto_type": null,
            "year": "`+row["year"]+`",
            "phone": `+row["phone"]+`,
            "email": "`+row["email"]+`"
        }
    }`
    )
});
}else{
  res.status('500').send('AUTH')
}
})

app.get("/x" , (req,res )=> {
  res.send('[]')
})






app.get("/api/governments" , (req,res) => {

  res.send('[{"value":1,"text":"\u0627\u0644\u0633\u0648\u064a\u0633"},{"value":2,"text":"\u0627\u0644\u0642\u0627\u0647\u0631\u0647"},{"value":3,"text":"\u0627\u0644\u0625\u0633\u0643\u0646\u062f\u0631\u064a\u0629"},{"value":4,"text":"\u0627\u0644\u0625\u0633\u0645\u0627\u0639\u064a\u0644\u064a\u0629"},{"value":5,"text":"\u0623\u0633\u0648\u0627\u0646"},{"value":6,"text":"\u0623\u0633\u064a\u0648\u0637"},{"value":7,"text":"\u0627\u0644\u0623\u0642\u0635\u0631"},{"value":8,"text":"\u0627\u0644\u0628\u062d\u0631 \u0627\u0644\u0623\u062d\u0645\u0631"},{"value":9,"text":"\u0627\u0644\u0628\u062d\u064a\u0631\u0629"},{"value":10,"text":"\u0628\u0646\u064a \u0633\u0648\u064a\u0641"},{"value":11,"text":"\u0628\u0648\u0631\u0633\u0639\u064a\u062f"},{"value":12,"text":"\u062c\u0646\u0648\u0628 \u0633\u064a\u0646\u0627\u0621"},{"value":13,"text":"\u0627\u0644\u062c\u064a\u0632\u0629"},{"value":14,"text":"\u0627\u0644\u062f\u0642\u0647\u0644\u064a\u0629"},{"value":15,"text":"\u062f\u0645\u064a\u0627\u0637"},{"value":16,"text":"\u0633\u0648\u0647\u0627\u062c"},{"value":17,"text":"\u0627\u0644\u0634\u0631\u0642\u064a\u0629"},{"value":18,"text":"\u0634\u0645\u0627\u0644 \u0633\u064a\u0646\u0627\u0621"},{"value":19,"text":"\u0627\u0644\u063a\u0631\u0628\u064a\u0629"},{"value":20,"text":"\u0627\u0644\u0641\u064a\u0648\u0645"},{"value":21,"text":"\u0627\u0644\u0642\u0644\u064a\u0648\u0628\u064a\u0629"},{"value":22,"text":"\u0642\u0646\u0627"},{"value":23,"text":"\u0643\u0641\u0631 \u0627\u0644\u0634\u064a\u062e"},{"value":24,"text":"\u0645\u0637\u0631\u0648\u062d"},{"value":25,"text":"\u0627\u0644\u0645\u0646\u0648\u0641\u064a\u0629"},{"value":26,"text":"\u0627\u0644\u0645\u0646\u064a\u0627"},{"value":27,"text":"\u0627\u0644\u0648\u0627\u062f\u064a \u0627\u0644\u062c\u062f\u064a\u062f"}]')
})


app.get("/sanctum/csrf-cookie" , (req,res) => {res.send(`[
  {
      "value": 1,
      "text": "\u0627\u0644\u0633\u0648\u064a\u0633"
  },
  {
      "value": 2,
      "text": "\u0627\u0644\u0642\u0627\u0647\u0631\u0647"
  },
  {
      "value": 3,
      "text": "\u0627\u0644\u0625\u0633\u0643\u0646\u062f\u0631\u064a\u0629"
  },
  {
      "value": 4,
      "text": "\u0627\u0644\u0625\u0633\u0645\u0627\u0639\u064a\u0644\u064a\u0629"
  },
  {
      "value": 5,
      "text": "\u0623\u0633\u0648\u0627\u0646"
  },
  {
      "value": 6,
      "text": "\u0623\u0633\u064a\u0648\u0637"
  },
  {
      "value": 7,
      "text": "\u0627\u0644\u0623\u0642\u0635\u0631"
  },
  {
      "value": 8,
      "text": "\u0627\u0644\u0628\u062d\u0631 \u0627\u0644\u0623\u062d\u0645\u0631"
  },
  {
      "value": 9,
      "text": "\u0627\u0644\u0628\u062d\u064a\u0631\u0629"
  },
  {
      "value": 10,
      "text": "\u0628\u0646\u064a \u0633\u0648\u064a\u0641"
  },
  {
      "value": 11,
      "text": "\u0628\u0648\u0631\u0633\u0639\u064a\u062f"
  },
  {
      "value": 12,
      "text": "\u062c\u0646\u0648\u0628 \u0633\u064a\u0646\u0627\u0621"
  },
  {
      "value": 13,
      "text": "\u0627\u0644\u062c\u064a\u0632\u0629"
  },
  {
      "value": 14,
      "text": "\u0627\u0644\u062f\u0642\u0647\u0644\u064a\u0629"
  },
  {
      "value": 15,
      "text": "\u062f\u0645\u064a\u0627\u0637"
  },
  {
      "value": 16,
      "text": "\u0633\u0648\u0647\u0627\u062c"
  },
  {
      "value": 17,
      "text": "\u0627\u0644\u0634\u0631\u0642\u064a\u0629"
  },
  {
      "value": 18,
      "text": "\u0634\u0645\u0627\u0644 \u0633\u064a\u0646\u0627\u0621"
  },
  {
      "value": 19,
      "text": "\u0627\u0644\u063a\u0631\u0628\u064a\u0629"
  },
  {
      "value": 20,
      "text": "\u0627\u0644\u0641\u064a\u0648\u0645"
  },
  {
      "value": 21,
      "text": "\u0627\u0644\u0642\u0644\u064a\u0648\u0628\u064a\u0629"
  },
  {
      "value": 22,
      "text": "\u0642\u0646\u0627"
  },
  {
      "value": 23,
      "text": "\u0643\u0641\u0631 \u0627\u0644\u0634\u064a\u062e"
  },
  {
      "value": 24,
      "text": "\u0645\u0637\u0631\u0648\u062d"
  },
  {
      "value": 25,
      "text": "\u0627\u0644\u0645\u0646\u0648\u0641\u064a\u0629"
  },
  {
      "value": 26,
      "text": "\u0627\u0644\u0645\u0646\u064a\u0627"
  },
  {
      "value": 27,
      "text": "\u0627\u0644\u0648\u0627\u062f\u064a \u0627\u0644\u062c\u062f\u064a\u062f"
  }
]`)})



app.get("/api/user/prepaid_courses" , (req,res) => {

  res.send('0')
})




app.post("/api/subscriptions", restrictToAdmin, (req,res) => {
 
  
  const data = req.body
  const sqlx = `
      UPDATE users
      SET
        
        balance = balance + "${data.balance}"
      
      WHERE
        phone = ${data.phone}
    `;

  db.get(sqlx, (err) => {
    if (err) {
      throw err;
    }
    
    res.statusCode=201
    
    res.send({"status":"successful"})
});

})

app.post("/api/sections/:id", restrictToAdmin, (req,res) => {
 
  
  const data = req.body
  const sqlx = `
      UPDATE section
      SET
        
        section_name = "${data.section_name}",
        section_description = "${data.section_description}",
        year = ${data.year},
        division_id = ${data.division_id}
      WHERE
        idx = ${req.params.id}
    `;

  db.get(sqlx, (err) => {
    if (err) {
      throw err;
    }
    
    res.statusCode=201
    
    res.send({"status":"successful"})
});

})

app.get("/api/sections/:id", (req,res) => {
  db.get(`SELECT * FROM section WHERE idx = ${req.params.id}`, (err, row) => {
    if (row) {
      res.send({
        "status": "success",
        "data": {
          "id": row.section_id,
          "section_name": row.section_name,
          "year": row.year,
          "division_id": row.division_id
        }
      }
      )
      console.log(row)
      console.log(`SELECT * FROM section WHERE idx = ${req.params.id}`)
    }else{res.send('err');console.log(`SELECT * FROM section WHERE idx = ${req.params.id}`)}})
    
  
})

app.post("/api/sections",restrictToAdmin, (req, res) => {
  const { section_name, section_description, year, course_id, division_id } = req.body;

  // Validate the required fields
  if (!section_name || !section_description) {
    return res.status(400).json({ error: "All fields are required." });
  }


  // Create an SQL query to insert the data into the "sections" table
  const query = `INSERT INTO section (section_name, section_description, year, course_id, division_id) VALUES (?, ?, ?, ?, ?)`;
  const values = [section_name, section_description, year, course_id, division_id];

 

  db.get(query, values, (err) => {
    if (err) {
      throw err;
    }
    res.status(201).json({ message: "Data inserted successfully." });

  });
});



app.get("/api/courses/:id/sections/options" ,restrictToAdmin, (req,res) => {
  const query = `SELECT * FROM section WHERE course_id = ${req.params.id}`;

  // Initialize an empty array to store the formatted data
  const formattedData = [];
  
  // Execute the query and process the results
  db.all(query, [], (err, rows) => {
    if (err) {
      throw err;
    }
  
    // Format each row and push it to the 'formattedData' array
    rows.forEach((row) => {
      const formattedRow = {
        value: row.idx.toString(), // Assuming 'id' is the unique identifier in your table
        text: row.section_name, // Assuming 'name' is the text you want to display
      };
      formattedData.push(formattedRow);
    });
  res.send(formattedData)
}

)})


app.get("/api/courses/:id/sections" , restrictToAdmin,(req,res) => {
 
  const sectionsData = [
    {
      section_id: 'section1',
      section_name: 'Section 1',
      section_description: 'Description for Section 1',
    },
    {
      section_id: 'section2',
      section_name: 'Section 2',
      section_description: 'Description for Section 2',
    },
    // Add more sections as needed
  ];
  
  // Emulate a sample response
  const emulateResponse = {
    message: 'Sections retrieved successfully',
    sections: sectionsData,
  };
  res.send(emulateResponse)
})




app.post("/api/unsubscriptions" ,restrictToAdmin, (req,res) => {
  const sql = `DELETE FROM users WHERE phone = ?`;

  db.run(sql, [parseInt(req.body.phone)], function (err) {
    if (err) {
      console.error('Error deleting record:', err.message);
    } else {
      res.status(201).send("deleted")
    }
  });
})

app.delete("/api/sections/:id" , restrictToAdmin,(req,res) => {
  const sql = `DELETE FROM section WHERE idX = ?`;

  db.run(sql, [req.params.id], function (err) {
    if (err) {
      console.error('Error deleting record:', err.message);
    } else {
      res.status(201).send("deleted")
    }
  });
})












app.post("/api/partitions" ,restrictToAdmin, (req,res) => {
  const videoData = {
    name: req.body.name,
    choosen_year: req.body.year,
    division_id: req.body.division_id,


  };
  
  // SQL query to insert data into the "video" table
  const insertQuery = `
    INSERT INTO partitions (name, year, division_id)
    VALUES (?, ?, ?)
  `;
  
  // Execute the insertion
  db.run(insertQuery, Object.values(videoData), function(err) {
    if (err) {
      console.error(err.message);
    } else {
      console.log(`Row inserted with ID: ${this.lastID}`);
      res.statusCode = 204
      res.send('ok')
    }})
})


app.get("/api/years/:id/partitions/options" , restrictToAdmin,(req,res) => {
  const query = `SELECT * FROM partitions WHERE year = ${req.params.id}`;
  
  // Initialize an empty array to store the formatted data
  const formattedData = [];
  
  // Execute the query and process the results
  db.all(query, [], (err, rows) => {
    if (err) {
      throw err;
    }
    // Format each row and push it to the 'formattedData' array
    rows.forEach((row) => {
      
      const formattedRow = {
        value: row.partition_id.toString(), // Assuming 'id' is the unique identifier in your table
        text: row.name, // Assuming 'name' is the text you want to display
      };
      formattedData.push(formattedRow);
     
    });
  res.send(formattedData)
}

)})





app.post("/api/questions",restrictToAdmin, (req,res) => {
  let xx=[]

  if (req.body.have_picture == 1){
    const file = req.files.picture;
  const path = __dirname + "/pub/questions/" + file.md5+'.png';
  file.mv(path, (err) => {
    if (err) {
      return res.status(500).send(err);
    }
    let asds = ''
  });
  xx['z'] = 'picture,'
  xx['x']= "'questions/"+file.md5+".png',"
  }else{
    xx['z'] = ''
  xx['x']= ""
  }
  const data = req.body
  const sqlx = `INSERT INTO questions (title,${xx['z']} level, shuffle_answers, answer_1, answer_2, answer_3, answer_4, correct_answer, division_id, year, partition_id, partition_name) VALUES (?, ${xx['x']}?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
  console.log(sqlx)
  db.get(sqlx, [data.title,data.level,data.shuffle_answers,data.answer_1,data.answer_2,data.answer_3,data.answer_4,data.correct_answer,data.division_id,data.year,data.partition_id,data.partition_name], (err) => {
    if (err) {
      throw err;
    }
    res.statusCode=201
    res.send('losl adiah kaw numen sento va casnes')
});

})




app.post("/api/videos" , restrictToAdmin,(req,res) => {
  const videoData = {
    name: req.body.name,
    description: req.body.description,
    duration: req.body.duration,
    is_free: req.body.is_free,
    platform: req.body.platform,
    source: req.body.source,
    have_quiz: req.body.have_quiz,
    division_id: req.body.division_id,
    visible_from: req.body.visible_from,
    visible_to: req.body.visible_to,
    year: req.body.choosen_year,
    add_to_course: req.body.add_to_course,
    course_id: req.body.course_id,
    section_id: req.body.section_id,
    division_name: req.body.division_name,
    section_name: req.body.section_name,
    section_description: req.body.section_description,
  };
  
  // SQL query to insert data into the "video" table
  const insertQuery = `
    INSERT INTO video (name, description, duration, is_free, platform, source, have_quiz, division_id, visible_from, visible_to, year, add_to_course, course_id, section_id, division_name, section_name, section_description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  
  // Execute the insertion
  db.run(insertQuery, Object.values(videoData), function(err) {
    if (err) {
      console.error(err.message);
    } else {
      console.log(`Row inserted with ID: ${this.lastID}`);
      res.statusCode = 204
      res.send('ok')
    }})
})




app.post('/api/videos/:videoId',restrictToAdmin, (req, res) => {
  const videoId = req.params.videoId;
  const videoData = req.body;

  const updateQuery = `
    UPDATE video
    SET name = ?, description = ?, duration = ?, is_free = ?, platform = ?, source = ?, have_quiz = ?, division_id = ?, visible_from = ?, visible_to = ?, year = ?, add_to_course = ?, course_id = ?, section_id = ?, division_name = ?, section_name = ?, section_description = ?
    WHERE id = ?
  `;

  db.run(
    updateQuery,
    [
      videoData.name,
      videoData.description,
      videoData.duration,
      videoData.is_free,
      videoData.platform,
      videoData.source,
      videoData.have_quiz,
      videoData.division_id,
      videoData.visible_from,
      videoData.visible_to,
      videoData.year,
      videoData.add_to_course,
      videoData.course_id,
      videoData.section_id,
      videoData.division_name,
      videoData.section_name,
      videoData.section_description,
      videoId, // The ID of the video to update
    ],
    function (err) {
      if (err) {
        console.error(err.message);
        res.status(500).send('Error updating data in the database.');
      } else {
        console.log(`Row updated for video ID: ${videoId}`);
        res.status(204).send('Data updated successfully.');
      }
    }
  );
});


app.delete("/api/videos/:id" , restrictToAdmin,(req,res) => {
  const sql = `DELETE FROM video WHERE id = ?`;

  db.run(sql, [req.params.id], function (err) {
    if (err) {
      console.error('Error deleting record:', err.message);
    } else {
      res.status(204).send("deleted")
    }
  });
})



app.get("/api/videos/paginate",restrictToAdmin, (req, res) => {
  console.log('asd')
  let query = `SELECT * FROM video `
  db.all(query, (err, rows) => {
    if (err) {
      console.error(err.message);
    }
    console.log(query)
    // Iterate over the rows array and print the name property of each object
    if (rows){
    
    res.json({
      "status": "success",
      "data": rows,
      "pagination": {
        "current_page": 1,
        "last_page": 3,
        "total": 20
      }
    }
    );
}})
}
)


app.get("/api/videos/:id", restrictToAdmin,(req, res) => {
  db.get(`SELECT * FROM video WHERE id = ?`, [req.params.id], (err, row) => {
    if (err) {
        console.error(err.message);
        res.send("fuck");
    } else {
        
        res.send(row);
    }
});
})

app.get("/api/years/:yr/videos/options" ,restrictToAdmin, (req,res) => {
  const query = `SELECT * FROM video WHERE year = ${req.params.yr}`;

  // Initialize an empty array to store the formatted data
  const formattedData = [];
  
  // Execute the query and process the results
  db.all(query, [], (err, rows) => {
    if (err) {
      throw err;
    }
  
    // Format each row and push it to the 'formattedData' array
    rows.forEach((row) => {
      const formattedRow = {
        value: row.id.toString(), // Assuming 'id' is the unique identifier in your table
        text: row.name, // Assuming 'name' is the text you want to display
      };
      formattedData.push(formattedRow);
    });
  res.send(formattedData)
}

)})
















app.post("/api/exams", restrictToAdmin,(req,res) => {


  const data = req.body
  const sqlx = "INSERT INTO exams (name, description, type, partition_id, quantities, pass_from, duration, best_duration, visible_from, visible_to, is_continuable, show_results, shuffle_questions, shuffle_partitions, exam_open_limit, division_id, year, id, add_to_course, section_name, section_description, course_id, section_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
  db.get(sqlx, [data.name,  data.description,  data.type,  data.partition_id,  data.quantities,  data.pass_from,  data.duration,  data.best_duration,  data.visible_from,  data.visible_to,  data.is_continuable,  data.show_results,  data.shuffle_questions,  data.shuffle_partitions,  data.exam_open_limit,  data.division_id,  data.year,  data.id,  data.add_to_course,  data.section_name,  data.section_description,  data.course_id,  data.section_id], (err) => {
    if (err) {
      throw err;
    }
    res.statusCode=204
    res.send('fuck')
});

})


app.get("/api/years/:yr/exams/options" , restrictToAdmin, (req,res) => {
  const query = `SELECT * FROM exams WHERE year = ${req.params.yr}`;

  // Initialize an empty array to store the formatted data
  const formattedData = [];
  
  // Execute the query and process the results
  db.all(query, [], (err, rows) => {
    if (err) {
      throw err;
    }
  
    // Format each row and push it to the 'formattedData' array
    rows.forEach((row) => {
      const formattedRow = {
        value: row.id.toString(), // Assuming 'id' is the unique identifier in your table
        text: row.name, // Assuming 'name' is the text you want to display
      };
      formattedData.push(formattedRow);
    });
  res.send(formattedData)
}

)})



app.delete("/api/exams/:id" ,restrictToAdmin, (req,res) => {
  const sql = `DELETE FROM exams WHERE id = ?`;

  db.run(sql, [req.params.id], function (err) {
    if (err) {
      console.error('Error deleting record:', err.message);
    } else {
      res.status(204).send("deleted")
    }
  });
})




app.post("/api/sexams", restrictToAdmin,(req, res) => {
  const data = req.body;
  const sqlx = `
    UPDATE exams
    SET
      name = ?,
      description = ?,
      type = ?,
      partition_id = ?,
      quantities = ?,
      pass_from = ?,
      duration = ?,
      best_duration = ?,
      visible_from = ?,
      visible_to = ?,
      is_continuable = ?,
      show_results = ?,
      shuffle_questions = ?,
      shuffle_partitions = ?,
      exam_open_limit = ?,
      division_id = ?,
      year = ?,
      add_to_course = ?,
      section_name = ?,
      section_description = ?,
      course_id = ?,
      section_id = ?
    WHERE id = ?;`;

  const values = [
    data.name,
    data.description,
    data.type,
    data.partition_id,
    data.quantities,
    data.pass_from,
    data.duration,
    data.best_duration,
    data.visible_from,
    data.visible_to,
    data.is_continuable,
    data.show_results,
    data.shuffle_questions,
    data.shuffle_partitions,
    data.exam_open_limit,
    data.division_id,
    data.year,
    data.add_to_course,
    data.section_name,
    data.section_description,
    data.course_id,
    data.section_id,
    data.id // specify the unique identifier for the update
  ];

  db.run(sqlx, values, (err) => {
    if (err) {
      throw err;
    }
    res.statusCode = 204;
    res.send('Update successful');
  });
});






app.post("/api/books", restrictToAdmin,(req,res) => {
  const file = req.files.source;
  const path = __dirname + "/pub/books/" + file.md5+'.pdf';
  file.mv(path, (err) => {
    if (err) {
      let xx = 1
    }
    let xx = 2
  });

  const data = req.body
  const sqlx = "INSERT INTO books (name, description, source, division_id, year, visible_from, visible_to , add_to_course, course_id, section_id, division_name, section_name, section_description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  db.get(sqlx, [data.name, data.description,"books/"+file.md5+'.pdf' ,data.division_id, data.choosen_year,data.visible_from,data.visible_to,data.add_to_course, data.course_id,data.section_id,data.division_name,data.section_name,data.section_description], (err) => {
    if (err) {
      throw err;
    }
    res.statusCode=204
    res.send('fuck')
});

})





app.post("/api/books/:id",restrictToAdmin, (req, res) => {
  const fileId = req.params.id; // Get the ID from the URL parameter
  const data = req.body;

  // Construct the SQL UPDATE statement to exclude the "source" field
  const sqlx =
    "UPDATE books SET name=?, description=?, division_id=?, year=?, visible_from=?, visible_to=?, add_to_course=?, course_id=?, section_id=?, division_name=?, section_name=?, section_description=? WHERE bookx_id=?";

  db.run(
    sqlx,
    [
      data.name,
      data.description,
      data.division_id,
      data.choosen_year,
      data.visible_from,
      data.visible_to,
      data.add_to_course,
      data.course_id,
      data.section_id,
      data.division_name,
      data.section_name,
      data.section_description,
      fileId, // Use the ID from the URL parameter in the WHERE clause
    ],
    function (err) {
      if (err) {
        // Handle the database update error here
        res.status(500).send(err);
      } else {
        res.status(204).send('yeaaaah'); // Success, no content
      }
    }
  );
});

app.delete("/api/books/:id" ,restrictToAdmin, (req,res) => {
  const sql = `DELETE FROM books WHERE bookx_id = ?`;

  db.run(sql, [req.params.id], function (err) {
    if (err) {
      console.error('Error deleting record:', err.message);
    } else {
      res.status(204).send("deleted")
    }
  });
})


app.get("/api/books/:id", restrictToAdmin,(req, res) => {
  db.get(`SELECT * FROM books WHERE bookx_id = ?`, [req.params.id], (err, row) => {
    if (err) {
        console.error(err.message);
        res.send("fuck");
    } else {
        
        res.send(row);
    }
});
})

app.get('/api/user/wallet_invoices/paginate' , (req,res) => {
  res.send('/api/user/wallet_invoices/paginate')
})
app.post('/api/sellables/course/:l/sections/:hghg/sectionables/:ghgh/videos/:gg/video_views' , (req,res)=>{
  res.send('s')
})
app.get('/api/user/wallet_records/paginate', (req ,res) => {
  res.send('')
})
app.post('/api/user/charge_insert_auto' , (req ,res ) => {
  const authHeader = req.headers['authorization'];
  console.log(req.body.insert_auto_phone)
  const token = authHeader.split(' ')[1]
  db.get(`SELECT * FROM insert_autos WHERE code = ?`, [req.body.insert_auto_phone], (err, row) => {
   
    
    if(row){
    const sqlx = `
      UPDATE users
      SET
        
        balance = balance + `+row.balance.toString()+`
      
      WHERE
        token = "${token}"
    `;
    console.log(sqlx)
    db.get(sqlx, (err, rowx) => {
      const sqlxx = `DELETE FROM insert_autos WHERE code = ?`;

      db.run(sqlxx, [req.body.insert_auto_phone], function (err) {
        
      });
      res.status(201).send('{}')
      
  });
}
    
});
})













app.get("/api/sellables/not_renamed/subscribed", (req,res) => {
  const authHeader = req.headers['authorization'];
  
  const token = authHeader.split(' ')[1]
  db.get(`SELECT * FROM users WHERE token = ?`, [token], (err, rowzz) => {
    
  let xasdasda = rowzz.crs.toString().split(';')
  
  let xx = []


    const queryx = `SELECT * FROM course WHERE sellable = 1`;
  
    // Execute the query using db.all()
    db.all(queryx, (err, rows) => {
      if (err) {
        console.error(err.message);
      }
      // Iterate over the rows array and print the name property of each object
      if(rows){
      rows.forEach((row) => {
       if(xasdasda.includes(row.id.toString())){
        let x = {
          "id": row.id,
          "name": row.name,
          "description": row.description,
          "prepaidable": row.prepaidable,
          "picture": row.picture,
          "price": row.price,
          "is_couponable": row.is_couponable,
          "year": row.year,
          "is_couponable": row.is_couponable,
          "visible_alone": row.visible_alone,
          "have_certificate": 0,
          "current_index": row.id,
          "created_at": row.created_at,
          "updated_at": row.created_at,
          "subscriptions_count": 1 
        }
        xx.push(x)
      }
      })
      res.send(xx);
    }});
  
  });
})








app.post('/api/sellables/course/:id/subscribe_from_wallet' , (req ,res ) => {
  const authHeader = req.headers['authorization'];
  console.log(req.body.insert_auto_phone)
  const token = authHeader.split(' ')[1]
  db.get(`SELECT * FROM course WHERE id = ?`, [req.params.id], (err, row) => {
   
    
    if(row){
    const sqlx = `
      UPDATE users
      SET
        
        crs = crs  || ';`+req.params.id+`' 
      
      WHERE
        token = "${token}"
    `;
    console.log(sqlx)
    db.get(sqlx, (err, rowx) => {
      const sqlxx = `
      UPDATE users
      SET
        
        balance = balance - `+row.price.toString()+`
      
      WHERE
        token = "${token}"
    `;
      db.run(sqlxx, [req.body.insert_auto_phone], function (err) {
        
      });
      res.status(201).send('{}')
      
  });
}
    
});
})

app.get('/api/user/statistics',(req,res)=>{
  const authHeader = req.headers['authorization'];
  
  const token = authHeader.split(' ')[1]
  db.get(`SELECT * FROM users WHERE token = ?`, [token], (err, row) => {

  res.send(`{
    "total_videos_count": 0,
    "viewed_videos_count": 0,
    "total_exams_count": 0,
    "finished_exams_count": 0,
    "total_results": 0,
    "total_questions_quantity": 0,
    "total_video_view_count": `+row.vids.toString()+`,
    "total_video_view_duration": 0,
    "total_video_open_duration": 0,
    "total_exam_results_count": 0,
    "finished_exam_results_count": 0
}`)
    
});
})



app.get("/api/sellables/course/:crsid/sections/:sctn/sectionables/:id" , (req,res) => {
if (req.headers['dino']) {
  if (req.headers['dino'].includes('video')) {
    const authHeader = req.headers['authorization'];
  
    const token = authHeader.split(' ')[1]
      const sqlx = `
          UPDATE users
          SET
            
            vids = vids + 1
          
          WHERE
          token = "${token}"
        `;

      db.get(sqlx, (err) => {
        if (err) {
          throw err;
        }
        
    });


    db.get(`SELECT * FROM "video" WHERE section_id = ${req.params.sctn} AND course_id = ${req.params.crsid} AND id = ${req.params.id}`, (err, xs) => {
      if (err) {
          console.error(err.message);
          res.send("fuck");
      } else {
                
          let xx ={
            "id": xs.id,
            "name": xs.name,
            "description": xs.description,
            "duration": xs.duration,
            "is_free": xs.is_free,
            "platform": xs.platform,
            "source": xs.source,
            "encoding_status": "raw",
            "720p": null,
            "480p": null,
            "240p": null,
            "have_quiz": xs.have_quiz,
            "division_id": xs.division_id,
            "year": xs.year,
            "created_at": xs.datexx,
            "updated_at": xs.datexx,
            "otp": false
          }
          let lol = {
            "id": xs.id,
            "sectionable_type": "video",
            "sectionable_id": req.params.id,
            "section_id": xs.section_id,
            "view_limit": xs.view_limit,
            "exam_finish_limit": 0,
            "exam_open_limit": 0,
            "exam_resume_limit": 0,
            "visible_from": xs.visible_from,
            "visible_to": xs.visible_to,
            "index": xs.id,
            "is_locked_on": 0,
            "created_at": xs.datexx,
            "updated_at": null,
            "deleted_at": null,
            "sectionable": xx
          }
          res.send(lol)
      }
    });



    
  }
  










  if (req.headers['dino'].includes('book')) {


    db.get(`SELECT * FROM "books" WHERE section_id = ${req.params.sctn} AND course_id = ${req.params.crsid} AND bookx_id = ${req.params.id}`, (err, row) => {
      if (err) {
          console.error(err.message);
          res.send("fuck");
      } else {
                
          let xx ={
            "id": row.bookx_id,
            "name": row.name,
            "description": row.description,
            "source": row.source,
            "division_id": row.division_id,
            "year": row.year,
            "created_at": row.datexx,
            "updated_at": row.datexx,
            "otp": false
          } 
          let lol = {
            "id": row.bookx_id,
            "sectionable_type": "book",
            "sectionable_id": req.params.id,
            "section_id": req.params.sctn,
            "view_limit": 0,
            "exam_finish_limit": 0,
            "exam_open_limit": 0,
            "exam_resume_limit": 0,
            "visible_from": row.visible_from,
            "visible_to": row.visible_to,
            "index": row.bookx_id,
            "is_locked_on": 0,
            "created_at": row.datexx,
            "updated_at": row.datexx,
            "deleted_at": null,
            "sectionable": xx
            }
          res.send(lol)
      }
    });



    
  }
















  if (req.headers['dino'].includes('exam')) {


    db.get(`SELECT * FROM "exams" WHERE section_id = ${req.params.sctn} AND course_id = ${req.params.crsid} AND examx_id = ${req.params.id}`, (err, row) => {
      if (err) {
          console.error(err.message);
          res.send("fuck");
      } else {
                
          let lol = {
            "id": row.examx_id,
            "sectionable_type": "exam",
            "sectionable_id": req.params.id,
            "section_id": req.params.sctn,
            "view_limit": 0,
            "exam_finish_limit": 0,
            "exam_open_limit": row.exam_open_limit,
            "exam_resume_limit": 0,
            "visible_from": row.visible_from,
            "visible_to": row.visible_from,
            "index": row.id,
            "is_locked_on": 0,
            "created_at": row.datexx,
            "updated_at": null,
            "deleted_at": null,
            "sectionable": {
                "id": row.id,
                "name": row.name,
                "description": row.description,
                "question_quantity": row.quantities,
                "pass_from": row.pass_from,
                "duration": row.duration,
                "best_duration": row.best_duration,
                "is_continuable": row.is_continuable,
                "show_results": row.show_results,
                "shuffle_questions": row.shuffle_questions,
                "shuffle_partitions": row.shuffle_partitions,
                "division_id": row.division_id,
                "year": row.year,
                "type": "exam",
                "current_index": row.id,
                "created_at": row.datexx,
                "updated_at": row.datexx,
                "otp": false
            }
        }
          res.send(lol)
      }
    });



    
  }







}else{
  res.send('no dinosor')
}

})




app.get("/api/years/:yr/books/options" ,restrictToAdmin, (req,res) => {
  const query = `SELECT * FROM books WHERE year = ${req.params.yr}`;

  // Initialize an empty array to store the formatted data
  const formattedData = [];
  
  // Execute the query and process the results
  db.all(query, [], (err, rows) => {
    if (err) {
      throw err;
    }
  
    // Format each row and push it to the 'formattedData' array
    rows.forEach((row) => {
      const formattedRow = {
        value: row.bookx_id, // Assuming 'id' is the unique identifier in your table
        text: row.name, // Assuming 'name' is the text you want to display
      };
      formattedData.push(formattedRow);
    });
  res.send(formattedData)
}

)})





// Define your API routes here
app.get("/api/coupons/options", (req, res) => {
  // Handle the GET request for "/api/coupons/options" route
  // Implement the logic to fetch the coupons options and send the response
  res.json({ data: "Coupons options" });
});

app.get("/api/coupons/:id", (req, res) => {
  // Handle the GET request for "/api/coupons/:id" route
  // Implement the logic to fetch the coupon info based on the provided ID and send the response
  const couponId = req.params.id;
  res.json({ data: `Coupon info for ID ${couponId}` });
});

app.post("/api/coupons", (req, res) => {
  // Handle the POST request for "/api/coupons" route
  // Implement the logic to create a new coupon based on the request body and send the response
  const couponData = req.body;
  res.json({ data: "Coupon created" });
});


app.get("/api/sellables/subscribed" , (req,res) => {
  

})




app.get("/api/sellables/:id", (req, res) => {
  const authHeader = req.headers['authorization'];
  
  const token = authHeader.split(' ')[1]
  db.get(`SELECT * FROM users WHERE token = ?`, [token], (err, rowzz) => {
    
  let xasdasda = rowzz.crs.toString().split(';')
  db.get(`SELECT * FROM course WHERE id = ?`, [req.params.id], (err, row) => {
    if (err) {
        console.error(err.message);
        res.send("fuck");
    } else {
        const formattedData = {
            id: req.params.id,
            name: row.name,
            description: row.description,
            category_id: row.category_id,
            prepaidable: row.prepaidable,
            picture: row.picture,
            price: row.price,
            is_couponable: row.is_couponable,
            year: row.year,
            sellable: row.sellable,
            visible_alone: row.visible_alone,
            have_certificate: row.have_certificate,
            current_index: row.id,
            created_at: row.created_at,
            updated_at: row.updated_at,
            first_free_video: row.first_free_video,
            subscriptions_count: xasdasda.includes(row.id.toString()) ? 1 : 0,
            videos_count: "∞",
            books_count: "∞",
            exams_count: "∞",
            hms_count: "∞",
            video_quizzes_count: "∞",
            total_videos_duration: "∞",
            total_questions_quantity: "∞"
        };
        res.send(formattedData);
    }
  });});
})



app.get("/api/wallet_records/get_current_balance" , (req,res )=>{
  const authHeader = req.headers['authorization'];
  
  const token = authHeader.split(' ')[1]
  db.get(`SELECT * FROM users WHERE token = ?`, [token], (err, row) => {
    res.send(row.balance.toString())
});
})





app.get("/api/courses/paginate",restrictToAdmin, (req, res) => {
  
    let query = `SELECT * FROM course `
    db.all(query, (err, rows) => {
      if (err) {
        console.error(err.message);
      }
      console.log(query)
      // Iterate over the rows array and print the name property of each object
      if (rows){
      
      res.json({
        "status": "success",
        "data": rows,
        "pagination": {
          "current_page": 1,
          "last_page": 3,
          "total": 20
        }
      }
      );
  }})
}
)












// Define a route to handle the incoming requests
app.get("/api/users/paginate",restrictToAdmin, (req, res) => {
  
  // Retrieve the filter data from the request query parameters
  const result = {};

    // Iterate over the key-value pairs in the array
    Object.entries(req.query).forEach(([key, value]) => {
        // Assign each key to a variable name dynamically using the bracket notation
        // Set the value of the variable to be the value from the array
    if(value){
        if(key == "phone"){
          result[key] = `AND ${key} = ${parseInt(value)}`;
        }
        else if(key == "full_name"){
          result[key] = `AND (first_name || ' ' || last_name LIKE '${value}')`;
        
        }
        else if(key == "government_id"){
          if (value != 0){
          result[key] = `AND governament = "${value}"`;
          }
          else {result[key] = ''}
        }
        else{
          
          result[key] = `AND ${key} = "${value}"`;
          
        }
    }else{
          result[key] = ''
        }
    });
    let query = `SELECT * FROM users WHERE 1=1 ${result.full_name} ${result.phone} ${result.father_phone} ${result.email} ${result.government_id}`
    db.all(query, (err, rows) => {
      if (err) {
        console.error(err.message);
      }
      console.log(query)
      // Iterate over the rows array and print the name property of each object
      if (rows){
      
      res.json({
        "status": "success",
        "data": rows.map(({ token, timexs, ...item }) => ({
          ...item,
          full_name: `${item.first_name} ${item.last_name}`,
          created_at: timexs
        })),
        "pagination": {
          "current_page": 1,
          "last_page": 3,
          "total": 20
        }
      }
      );
  }});

  // Perform any necessary data validation or filtering here

  // Prepare the response data
  

  // Send the response with the filtered data
  /*res.json({
    "status": "success",
    "data": [
      {
        "id": 1,
        "full_name": "John Doe",
        "password_reset_count": 2,
        "phone": "1234567890",
        "father_phone": "9876543210",
        "email": "john.doe@example.com",
        "year": 3,
        "subscriptions_count": 5,
        "invoices_count": 10,
        "created_at": "2023-08-01T12:34:56Z"
      },
      {
        "id": 2,
        "full_name": "Jane Smith",
        "password_reset_count": 1,
        "phone": "5555555555",
        "father_phone": "1111111111",
        "email": "jane.smith@example.com",
        "year": 2,
        "subscriptions_count": 3,
        "invoices_count": 6,
        "created_at": "2023-07-15T09:30:00Z"
      },
      // Additional user objects...
    ],
    "pagination": {
      "current_page": 1,
      "last_page": 3,
      "total": 20
    }
  }
  );*/
});


app.post("/api/auth/register", Data_validation, (req, res) =>  {res.send(req.msg);})

app.post("/api/auth/logout", Get_data, (req, res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader.split(' ')[1]) {
    const sql = "INSERT INTO d_info (phone, type, operator, browser, op) VALUES (?, ?, ?, ?, ?)";
    db.get(sql, [req.xphone, req.xtype, req.os, req.xbrowser, 'logout'], (err) => {
      if (err) {
        throw err;
      }
    });
    res.status(201).send('{"message":"\u062a\u0645 \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062e\u0631\u0648\u062c \u0628\u0646\u062c\u0627\u062d"}');
   
  } else {
    res.sendStatus(422);
    res.send('token')
  }
})
app.post("/api/auth/login", (req, res) => {
  const Auth = new Manage();
  if(req.body.with_code == 1){
    console.log('x')
    console.log(Auth.docodeLogin(req.body, req,res));
  }else{
  if (validator.validate(req.body.email) || parseInt(req.body.phone)) {

    
    console.log('sa')
    console.log(Auth.doLogin(req.body, req,res));
 
    
  } else {
    res.statusCode = 422;
    res.send('{"message":"\u0644\u0627\u0632\u0645\u0020\u0627\u0644\u0628\u0631\u064a\u062f\u0020\u0627\u0644\u0625\u0644\u0643\u062a\u0631\u0648\u0646\u064a\u0020\u064a\u0628\u0642\u0627\u0020\u0635\u062d\u064a\u062d","errors":{"email":["\u0644\u0627\u0632\u0645\u0020\u0627\u0644\u0628\u0631\u064a\u062f\u0020\u0627\u0644\u0625\u0644\u0643\u062a\u0631\u0648\u0646\u064a\u0020\u064a\u0628\u0642\u0627\u0020\u0635\u062d\u064a\u062d"]}}')
  }
}
})
app.post("/api/auth/addLogin", (req, res) => {
  const Auth = new Manage();
  console.log(Auth.doLogin(req.body, res, obj.url));
})


// Get login tokens with pagination and filtering
app.get("/api/logout_tokens/paginate",restrictToAdmin, getname, async (req, res) => {
    
  let xx = {
    "data": []
  }

  let limitx = parseInt(req.query.per_page)
  let offset = (parseInt(req.query.page)-1) * limitx
  const query = `SELECT * FROM d_info WHERE phone = ${parseInt(req.query.phone)} AND op = 'login'  LIMIT ${limitx} OFFSET ${offset};`;


  // Execute the query using db.all()
  db.all(query, (err, rows) => {
    if (err) {
      console.error(err.message);
    }
    // Iterate over the rows array and print the name property of each object
    if (rows){
    for (let ii = 0; ii < rows.length; ii++) {
      const row = rows[ii];
      
       
        let x = {
          "id": ii+1,
          "tokenable": {
            "id": row.id,
            "phone": row.phone,
            "full_name": req.xnamex
          },
          "deleted_today": 2,
          "deleted_this_week": 5,
          "device_info": {
            "device_type": row.type,
            "device_name": "SEC_ERROR",
            "device_platform": row.operator,
            "device_browser": row.browser
          },
          "deleted_by": "app",
          "deleted_at": row.time_account_created,
          "last_used_at": row.time_account_created,
          "created_at": req.xcreatedx
        }
        xx.data.push(x)
    
    }
    res.json(xx);
}});



  
});

app.get("/api/login_tokens/paginate",restrictToAdmin,getname, async (req, res) => {
 if(req.query.phone){
  let xx = {
    "data": []
  }

  let limitx = parseInt(req.query.per_page)
  let offset = (parseInt(req.query.page)-1) * limitx
  const query = `SELECT * FROM d_info WHERE phone = ${parseInt(req.query.phone)} AND op = 'login'  LIMIT ${limitx} OFFSET ${offset};`;

  // Execute the query using db.all()
  db.all(query, (err, rows) => {
    if (err) {
      console.error(err.message);
    }
    // Iterate over the rows array and print the name property of each object
    if(rows){
    rows.forEach((row) => {
     
      let x = {
        "id": row.id,
        "tokenable": {
          "id": row.id,
          "phone": row.phone,
          "full_name": req.xnamex
        },
        "deleted_today": "NaN",
        "deleted_this_week": rows.length,
        "device_info": {
          "device_type": row.type,
          "device_name": "SEC_ERROR",
          "device_platform": row.operator,
          "device_browser": row.browser
        },
        "deleted_by": "app",
        "deleted_at": row.time_account_created,
        "last_used_at": row.time_account_created,
        "created_at": req.xcreatedx
      }
      xx.data.push(x)
    })
    res.json(xx);}else{res.send('[]')}
  });

 }else{
  res.send("")
 }
});

// Delete a login token
/*app.post("/tokens/:id/destroy", async (req, res) => {
  try {
    const token = await Token.findById(req.params.id);
    if (!token) {
      return res.status(404).json({ error: "Token not found" });
    }

    await token.remove();

    res.json({ message: "Token deleted successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
*/

app.post("/api/user/edit/prepaid_courses", (req,res) => {
  let text = req.body.phone
  let code = text.includes("auto_");
  let sum = (req.body.to_sum === 1) ? "55555555" : req.body.prepaid_courses;
  const codes = text.split(' ').filter(word => word.trim() !== '')
  let xxss = []
  
  // Iterate through each word using forEach
  codes.forEach(xx => {
      
    if (code) {
          const sqlx = `
          UPDATE insert_autos
          SET
            prepaid_courses = "${sum}"
          WHERE
            code = "${xx}"
        `;

        db.get(sqlx, (err) => {
          if (err) {
            throw err;
          }
          });
    }else{
          const sqlx = `
          UPDATE users
          SET
            prepaid = ${sum}
          WHERE
            phone = ${xx}
        `;

        db.get(sqlx, (err) => {
          if (err) {
            throw err;
          }
          getbphone(xx, (err, userData) => {
            
               
            xxss.push("{ prepaid_courses: 10 ,phone: userData.phone,name:userData.full_name, successful: sum}");
          
          });
          xxss.push("{ prepaid_courses: 10 ,phone: userData.phone,name:userData.full_name, successful: sum}");

        });

    }








  });
  console.log(xxss)

  res.status(201).json({
    message: "تم تحديث بيانات المستخدم بنجاح.",
    result: {
     "01020755232" : { prepaid_courses: sum ,phone: '010',name:'uiui', successful: sum}
    },
  });



  /*const data = req.body
  const sqlx = `
      UPDATE division
      SET
        name = "${data.name}"
      WHERE
        id = ${req.params.id}
    `;

  db.get(sqlx, (err) => {
    if (err) {
      throw err;
    }
    
    res.statusCode=201
    
    res.send({"status":"successful"}
});
*/
})

app.post("/api/insert_auto" ,restrictToAdmin,(req,res) => {
    
  const data = req.body
 for (let l = 0; l != parseInt(data.quantity); l++) {

  const sqlx = "INSERT INTO insert_autos (title, qq, code, balance) VALUES (?, ?, ?, ?)";
  let xx = "auto_"+crypto.encrypt(`${data.name}_${l}`)
   db.get(sqlx, [data.name, data.quantity, xx, data.balance], (err) => {
     if (err) {
       throw err;
     }
   })
 }
 
 res.statusCode=201
 res.send({"status":"successful"})
})

app.get("/api/insert_autos/paginate",restrictToAdmin, async (req, res) => {
  let xx = {
    "data": [],
    "total": 3,
    "page": 1,
    "perPage": 10
  }

  try {
    const queryx = `SELECT DISTINCT title,qq FROM insert_autos`;

    const rows = await new Promise((resolve, reject) => {
      db.all(queryx, (err, rows) => {
        if (err) {
          console.error(err.message);
          reject(err);
        }
        resolve(rows);
      });
    });

    if (rows) {
      for (const rowx of rows) {
        const row = await new Promise((resolve, reject) => {
          db.get(`SELECT * FROM insert_autos WHERE title = "${rowx.title}" LIMIT 1`, (err, row) => {
            if (err) {
              console.error(err.message);
              reject(err);
            }
            resolve(row);
          });
        });

        if (row) {
          let x = {
            "id": row.id,
            "name": row.title,
            "quantity": row.qq,
            "number_from": row.id,
            "number_to": row.id + row.qq,
            "created_at": row.created_at
          }
          xx.data.push(x);
        }
      }

      res.json(xx);
    } else {
      res.send('[]');
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/insert_auto/:rcode", async (req, res) => {
  try {
    const queryx = `SELECT * FROM insert_autos WHERE id = ${req.params.rcode}`;

    const rows = await new Promise((resolve, reject) => {
      db.get(queryx, (err, row) => {
        if (err) {
          console.error(err.message);
          reject(err);
        }
        resolve(row);
      });
    });

    if (rows) {
      let xxxs = []
      const row = await new Promise((resolve, reject) => {
        db.all(`SELECT * FROM insert_autos WHERE title = "${rows.title}"`, (err, rows) => {
          if (err) {
            console.error(err.message);
            reject(err);
          }
          resolve(rows);
        });
      });

      if (row && row.length > 0) {
        for(let lol of row){
          
        xxxs.push(`<tr>
        <td>${lol.title}</td>
        <td>${lol.code}</td>
        <td><button class="button" onclick="copyText('${lol.code}')">Copy</button></td>
      </tr>`);
        }
      
      } else {
        res.send([]);
      }
      res.send(`<html>
      <head>
      <style>
      table {
        border-collapse: collapse;
        width: 100%;
      }
      
      th, td {
        text-align: left;
        padding: 8px;
      }
      
      tr:nth-child(even) {
        background-color: #f2f2f2;
      }
      
      .button {
        background-color: #4CAF50;
        border: none;
        color: white;
        padding: 5px 10px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
      }
      </style>
      <script>
      function copyText(text) {
        var input = document.createElement("input");
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand("copy");
        document.body.removeChild(input);
      }
      
      function copyAllCodes() {
        var codes = [];
        var rows = document.getElementsByTagName("tr");
        for (var i = 1; i < rows.length; i++) {
          var cells = rows[i].getElementsByTagName("td");
          codes.push(cells[1].innerText);
        }
        copyText(codes.join(' '));
      }
      </script>
      </head>
      <body>
      
      <h2>Codes</h2>
      <button class="button" onclick="copyAllCodes()">Copy All Codes</button>
      
      
      <table>
        <tr>
          <th>Name</th>
          <th>Code</th>
          <th>Copy</th>
        </tr>
        ${xxxs.join(' ')}
        
      </table>
      
      </body>
      </html>
      `)
    } else {
      res.send([]);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


/*app.get("/insert_auto/:rcode" , (req,res) => {
  let xx= []
  const queryx = `SELECT * FROM insert_autos WHERE id = ${req.params.rcode}`;
  
  // Execute the query using db.all()
  db.all(queryx, (err, rows) => {
    if (err) {
      console.error(err.message);
    }
    // Iterate over the rows array and print the name property of each object
    if(rows){
    rows.forEach((row) => {
     
      xx.push(row.code)
    })
    res.json(xx);
  }});
})*/


app.post("/api/ana/init/" , (req,res) => {
  res.send("ss")
})
app.post("/api/ana/init/*" , (req,res) => {
  res.send("ss")
})
app.post("/api/users/search", (req, res) => {
    res.send(`{
      "status": 200,
      "data": {
        "id": 123,
        "full_name": "Ahmed Ali",
        "phone": "+201234567890",
        "email": "ahmed.ali@example.com",
        "role": "student",
        "courses": [
          {
            "id": 456,
            "name": "React for Beginners",
            "instructor": "Mohamed Salah",
            "progress": 75
          },
          {
            "id": 789,
            "name": "Advanced React",
            "instructor": "Sara Ahmed",
            "progress": 50
          }
        ]
      }
    }`)
});


app.post("/api/courses",restrictToAdmin, (req,res) => {
  const file = req.files.picture;
  const path = __dirname + "/pub/courses_images/" + file.md5+'.png';
  file.mv(path, (err) => {
    if (err) {
      return res.status(500).send(err);
    }
    return res.send({ status: "success", path: path });
  });

  const data = req.body
  const sqlx = "INSERT INTO course (name, description, picture, price, year, visible_alone, sellable , prepaidable, is_couponable) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
  db.get(sqlx, [data.name, data.description,"courses_images/"+file.md5+'.png' ,data.price, data.year,data.visible_alone,data.sellable,data.prepaidable, data.is_couponable], (err) => {
    if (err) {
      throw err;
    }
    res.statusCode=201
});

})


app.delete("/api/courses/:id" ,restrictToAdmin, (req,res) => {
  const sql = `DELETE FROM course WHERE id = ?`;

  db.run(sql, [req.params.id], function (err) {
    if (err) {
      console.error('Error deleting record:', err.message);
    } else {
      res.status('201').send("deleted")
    }
  });
})
app.get('/api/notifications/latest/:id',(req,res)=>{
  res.send('s')
})
app.post("/api/courses/:id",restrictToAdmin, (req,res) => {
  const now = new Date();
  const options = { timeZone: 'Europe/Berlin', timeZoneName: 'short', hour12: false };
  const timeFormatted = now.toLocaleString('en-US', options);

  const file=""
  if (req.files){
    const file = req.files.picture;
    const path = __dirname + "/pub/courses_images/" + file.md5+'.png';
    file.mv(path, (err) => {if (err) {return res.status(500).send(err);}});
  }
  
  const ifphot = req.files ? 'picture = "courses_images/'+req.files.picture.md5+'.png",' : "";
  const data = req.body
  const sqlx = `
      UPDATE course
      SET
        name = "${data.name}",
        description = "${data.description}",
        price = "${data.price}",
        sellable = ${data.sellable},
        visible_alone = ${data.visible_alone},
        prepaidable = ${data.prepaidable},
        is_couponable = ${data.is_couponable},
        ${ifphot}
        year = "${data.year}",
        updated_at = "${timeFormatted}"
      WHERE
        id = ${req.params.id}

    `;

  db.get(sqlx, (err) => {
    if (err) {
      throw err;
    }


    res.statusCode=201
    
  res.send({"status":"successful"})
});

})




app.get("/api/courses/:id",restrictToAdmin, (req,res) => {
  db.get(`SELECT * FROM course WHERE id = ${req.params.id}`, (err, row) => {
    if (row) {
      res.send({
        "picture": row.picture,
        "status": "success",
        "data": {
          "course_id": row.id,
          "name": row.name,
          "description": row.description,
          "price": row.price,
          "sellable": row.sellable,
          "visible_alone": row.visible_alone,
          "prepaidable": row.prepaidable,
          "is_couponable": row.is_couponable,
          "picture": row.picture,
          "choosen_year": row.year,
          "submit_type": "update"
        }
      }
      )
    }})
  
})
app.get("/api/sellables/year/:yr", (req,res) => {
  const authHeader = req.headers['authorization'];
  
  const token = authHeader.split(' ')[1]
  db.get(`SELECT * FROM users WHERE token = ?`, [token], (err, rowzz) => {

  let xx = []

  let xasdasda = rowzz ? rowzz.crs.toString().split(';') : []
    const queryx = `SELECT * FROM course WHERE sellable = 1 AND year = ${req.params.yr}`;
  
    // Execute the query using db.all()
    db.all(queryx, (err, rows) => {
      if (err) {
        console.error(err.message);
      }
      // Iterate over the rows array and print the name property of each object
      if(rows){
      rows.forEach((row) => {
       
        let x = {
          "id": row.id,
          "name": row.name,
          "description": row.description,
          "prepaidable": row.prepaidable,
          "picture": row.picture,
          "price": row.price,
          "is_couponable": row.is_couponable,
          "year": row.year,
          "is_couponable": row.is_couponable,
          "visible_alone": row.visible_alone,
          "have_certificate": 0,
          "current_index": row.id,
          "created_at": row.created_at,
          "updated_at": row.created_at,
          "subscriptions_count": xasdasda.includes(row.id.toString()) ? 1 : 0
        }
        xx.push(x)
      })
      res.send(xx);
    }});
  
  });
})

app.post("/api/tokens/:id/destroy" , (req,res) => {

  const id = req.query.id
  sqlx = "DELETE FROM users WHERE id = ?";
  db.get(sql, [id], (err) => {
  if (err) {throw err;}
});

})









app.post("/api/divisions/:id", (req,res) => {
 
  
  const data = req.body
  const sqlx = `
      UPDATE division
      SET
        
        name = "${data.name}",
        year = ${data.year},
        division_id = ${data.division_id}
      WHERE
        id = ${req.params.id}
    `;

  db.get(sqlx, (err) => {
    if (err) {
      throw err;
    }
    
    res.statusCode=201
    
    res.send({"status":"successful"})
});

})


app.delete("/api/divisions/:id" , (req,res) => {
  const sql = `DELETE FROM division WHERE id = ?`;

  db.run(sql, [req.params.id], function (err) {
    if (err) {
      console.error('Error deleting record:', err.message);
    } else {
      res.status(201).send("deleted")
    }
  });
})


app.get("/api/divisions/:id", (req,res) => {
  db.get(`SELECT * FROM division WHERE id = ${req.params.id}`, (err, row) => {
    if (row) {
      res.send({
        "status": "success",
        "data": {
          "id": row.id,
          "name": row.name,
          "year": row.year,
          "division_id": row.division_id
        }
      }
      )
    }})
  
})


 


app.post("/api/divisions" , (req,res) => {
  
const data = req.body
  const sqlx = "INSERT INTO division (name, year, division_id) VALUES (?, ?, ?)";
  db.get(sqlx, [data.name, data.year, data.division_id], (err) => {
    if (err) {
      throw err;
    }
    res.statusCode=201
    res.send({"status":"successful"})
})
})


app.get("/api/years/:yr/divisions/options" , (req,res) => {


  const query = `SELECT id, name FROM division WHERE year = ${req.params.yr}`;


  // Execute the query using db.all()
  let farr = []
  db.all(query, (err, rows) => {
    if (err) {
      console.error(err.message);
    }
    // Iterate over the rows array and print the name property of each object
    if (rows){
      rows.forEach((row) => {
        var xi = {}
        xi.value = row.id
        xi.text = row.name 
        xi.year = row.year
        farr.push(xi)
      });
    
    res.send(farr)
    }
  
})

})















app.get("/api/years/:yr/courses/options" ,restrictToAdmin, (req,res) => {


  const query = `SELECT id, name FROM course WHERE year = ${req.params.yr}`;


  // Execute the query using db.all()
  let farr = []
  db.all(query, (err, rows) => {
    if (err) {
      console.error(err.message);
    }
    // Iterate over the rows array and print the name property of each object
    if (rows){
      rows.forEach((row) => {
        var xi = {}
        xi.value = row.id
        xi.text = row.name 
        farr.push(xi)
      });
    
    res.send(farr)
    }
  
})

})



//admin routes
app.post('/api/auth/admin/login' , (req,res) => {const Auth = new Manage();console.log(Auth.doaLogin(req.body,res));})
app.post("/api/users", Data_validation, (req, res) =>  {if(checkadmin(req)){res.send(req.msg);}else{res.sendStatus(422);res.send('token');}})
//app.post("/api/users/search", (req, res) =>  {checkadmin(req,res,search)})

/*
app.options("/api/admin_pages_allow" , (req,res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader.split(' ')[1]=="e69d5e9c19fcb49c0bsc47e6f7fe82977"){
    res.statusCode = 204;
    
  }else{
    res.statusCode = 422;
    res.send('MotherFucker')
  }
})

*/








































































app.get('/lol', (req ,res )=>{
  let sectionx = [];
  



  
}
)




app.get('/api/sellables/course/:id/content', async (req, res) => {
  const courseIdToFetch = req.params.id; // Replace with the desired course_id
  const coursex = [];
  const sql = `SELECT * FROM course WHERE id = ?`;

  db.get(sql, [courseIdToFetch], async (err, cc) => {
    if (err) {
      console.error(err.message);
    } else {
      if (cc) {
        const query = `
        SELECT *
        FROM section
        WHERE course_id = ?;
        `;

        const ssc = await new Promise((resolve, reject) => {
          db.all(query, [courseIdToFetch], (err, rows) => {
            if (err) {
              console.error(err.message);
              reject(err);
            } else {
              resolve(rows);
            }
          });
        });

        for (const ss of ssc) {
          let sectionx = [];
          const sectionId = ss.idx;
          const combinedData = [];

          const booksDataPromise = new Promise((resolve, reject) => {
            db.all(`SELECT * FROM "books" WHERE section_id = ${sectionId}`, (err, booksData) => {
              if (err) {
                console.error(err.message);
                reject(err);
              } else {
                resolve(booksData);
              }
            });
          });

          const examsDataPromise = new Promise((resolve, reject) => {
            db.all(`SELECT * FROM "exams" WHERE section_id = ${sectionId}`, (err, examsData) => {
              if (err) {
                console.error(err.message);
                reject(err);
              } else {
                resolve(examsData);
              }
            });
          });

          const videoDataPromise = new Promise((resolve, reject) => {
            db.all(`SELECT * FROM "video" WHERE section_id = ${sectionId}`, (err, videoData) => {
              if (err) {
                console.error(err.message);
                reject(err);
              } else {
                resolve(videoData);
              }
            });
          });

          const [booksData, examsData, videoData] = await Promise.all([booksDataPromise, examsDataPromise, videoDataPromise]);

          // Push the data from 'books', 'exams', and 'video' into the combined array
          combinedData.push(...booksData, ...examsData, ...videoData);

          // Sort the combined data by the 'datexx' column
          combinedData.sort((a, b) => new Date(a.datexx) - new Date(b.datexx));

          for (const xs of combinedData) {
            // Create and push datax objects based on conditions

            if ('platform' in xs) {
              datax = {
                "id": xs.id,
                "sectionable_type": "video",
                "sectionable_id": xs.id,
                "section_id": xs.section_id,
                "view_limit": 0,
                "exam_finish_limit": 0,
                "exam_open_limit": 0,
                "exam_resume_limit": 0,
                "visible_from": xs.visible_from,
                "visible_to": xs.visible_to,
                "index": 1,
                "is_locked_on": 0,
                "created_at": null,
                "updated_at": null,
                "deleted_at": null,
                "is_locked": false,
                "sectionable": {
                  "id": xs.vid,
                  "name": xs.name,
                  "description": xs.description,
                  "duration": xs.duration,
                  "is_free": xs.is_free,
                  "view_limit": 6,
                  "platform": xs.platform,
                  "source": xs.source,
                  "encoding_status": "raw",
                  "720p": null,
                  "480p": null,
                  "240p": null,
                  "have_quiz": xs.have_quiz,
                  "division_id": xs.division_id,
                  "year": xs.year,
                  "created_at": xs.visible_from,
                  "updated_at": xs.visible_from,
                  "limit_reached": false,
                  "video_views_count": 0,
                  "last_current_time": 0,
                  "video_opened_count": 0,
                  "total_time_opened": 0,
                  "total_time_played": 0
                }
              };
              sectionx.push(datax);
            }else if ('bookx_id' in xs) {
              datax = {
                "id": xs.bookx_id,
                "sectionable_type": "book",
                "sectionable_id": crypto.ien(xs.datexx),
                "section_id": xs.section_id,
                "view_limit": 0,
                "exam_finish_limit": 0,
                "exam_open_limit": 0,
                "exam_resume_limit": 0,
                "visible_from": xs.visible_from,
                "visible_to": xs.visible_to,
                "index": 4,
                "is_locked_on": 0,
                "created_at": null,
                "updated_at": null,
                "deleted_at": null,
                "sectionable": {
                  "id": xs.bookx_id,
                  "name": xs.name,
                  "description": xs.description,
                  "source": xs.source,
                  "division_id": xs.division_id,
                  "year": xs.year,
                  "created_at": xs.visible_from,
                  "updated_at": xs.visible_from
                }
              };
              sectionx.push(datax);
            } else if ('examx_id' in xs) {
              datax = {
                "id": xs.examx_id,
                "sectionable_type": xs.type,
                "sectionable_id": crypto.ien(xs.datexx),
                "section_id": xs.section_id,
                "view_limit": 0,
                "exam_finish_limit": 0,
                "exam_open_limit": xs.exam_open_limit,
                "exam_resume_limit": 0,
                "visible_from": xs.visible_from,
                "visible_to": xs.visible_to,
                "index": 2,
                "is_locked_on": 0,
                "created_at": null,
                "updated_at": null,
                "deleted_at": null,
                "is_locked": false,
                "key_item": false,
                "sectionable": {
                  "id": xs.examx_id,
                  "name": xs.name,
                  "description": xs.description,
                  "question_quantity": xs.quantities,
                  "pass_from": xs.pass_from,
                  "duration": xs.duration,
                  "best_duration": xs.best_duration,
                  "is_continuable": xs.is_continuable,
                  "show_results": xs.show_results,
                  "shuffle_questions": xs.shuffle_answers,
                  "shuffle_partitions": xs.shuffle_partitions,
                  "division_id": xs.division_id,
                  "year": xs.year,
                  "type": xs.type,
                  "current_index": 2,
                  "created_at": xs.visible_from,
                  "updated_at": xs.visible_from,
                  "exam_results_count": 0,
                  "exam_results_finished_count": 0,
                  "exam_results_medium": 0,
                  "exam_results_medium_percentage": 0,
                  "exam_results_max_result": 0,
                  "exam_results_max_result_percentage": 0,
                  "exam_results_min_result": 0,
                  "exam_results_min_result_percentage": 0
                }
              };
              sectionx.push(datax);
            }
          }

          let lol = {
            "id": ss.idx,
            "name": ss.section_name,
            "description": ss.section_description,
            "current_index": ss.idx,
            "created_at": cc.created_at,
            "updated_at": cc.created_at,
            "deleted_at": null,
            "sectionables": sectionx, // Push 'sectionx' after the inner queries have completed
            "pivot": {
              "course_id": ss.course_id,
              "section_id": ss.idx,
              "index": ss.idx
            }
          };
          coursex.push(lol);
        }

        res.send(JSON.stringify(coursex, null, 2));
      } else {
        console.log(`No course found with ID`);
      }
    }
  });
});









app.get("/api/sellables/course/11/sections/:sectr/sectionables/:vid" ,(req,res) =>{
  coursei = 10
  const sql = 'SELECT * FROM video WHERE id = ? AND course_id = ? AND section_id = ?';

// Execute the SQL query with the specified ID.
db.get(sql, [req.params.vid  ,coursei,  req.params.sectr], (err, row) => {
  if (err) {
    console.error(err.message);
  } else {
    if (row) {
      let vs =row
      data = {
        "id": vs.id,
        "sectionable_type": "video",
        "sectionable_id": vs.section_id,
        "section_id": vs.section_id,
        "view_limit": 0,
        "exam_finish_limit": 0,
        "exam_open_limit": 0,
        "exam_resume_limit": 0,
        "visible_from": vs.visible_from,
        "visible_to": vs.visible_to,
        "index": 1,
        "is_locked_on": 0,
        "created_at": null,
        "updated_at": null,
        "deleted_at": null,
        "is_locked": false,
        "sectionable": {
          "id": vs.id,
          "name": vs.name,
          "description": vs.description,
          "duration": vs.duration,
          "is_free": vs.is_free,
          "view_limit": 6,
          "platform": vs.platform,
          "source": vs.source,
          "encoding_status": "raw",
          "720p": null,
          "480p": null,
          "240p": null,
          "have_quiz": vs.have_quiz,
          "division_id": vs.division_id,
          "year": vs.year,
          "created_at": null,
          "updated_at": null,
          "limit_reached": false,
          "video_views_count": 0,
          "last_current_time": 0,
          "video_opened_count": 0,
          "total_time_opened": 0,
          "total_time_played": 0
        }
      };
    res.send(data)
    } else {
      res.statusCode(404)
    }
  }

})})

 
app.post("/api/sellables/course/:xid/subscribe_pre_request", (req,res)=>{

  db.get(`SELECT * FROM course WHERE id = ?`, [req.params.xid], (err, row) => {
    if (err) {
        console.error(err.message);
        res.send("fuck");
    } else {
            db.get(`SELECT * FROM invoices WHERE for_course = ? AND user_token = ?`, [req.params.xid,req.headers['authorization'].split(' ')[1]], (err, rowx) => {
              if (err) {
                  console.error(err.message);
                  res.send("fuck");
              } else {
                if(rowx){
                  res.send(`{
                    "previous_invoices": [
                        {
                            "id": ${rowx.id},
                            "user_id": 0,
                            "visitor_visit_id": 0,
                            "have_subscriptions": 1,
                            "quantity": 1,
                            "total_price": "${rowx.total}",
                            "coupon_id": null,
                            "discount": "0.00",
                            "invoice_status": "${rowx.invoice_status}",
                            "is_fetched": 0,
                            "last_fetched_invoice_status_at": "0",
                            "payment_time": null,
                            "invoice_id": "${rowx.invoice_id}",
                            "invoice_key": "${rowx.invoice_ref}",
                            "invoice_provider": "shakeout",
                            "payment_method": null,
                            "reference_number": null,
                            "created_at": "${rowx.date}",
                            "updated_at": "${rowx.date}",
                            "invoice_subscriptions": [
                                {
                                    "id": ${rowx.id},
                                    "user_id": 0,
                                    "invoice_id": ${rowx.id},
                                    "invoice_subscriptionable_type": "course",
                                    "invoice_subscriptionable_id": ${row.id},
                                    "price": ${rowx.total},
                                    "discount": "0.00",
                                    "created_at": "${rowx.date}",
                                    "updated_at": "${rowx.date}"
                                }
                            ]
                        }
                    ],
                    "course": {
                        "id": ${row.id},
                        "name": "${row.name}",
                        "description": "${row.description}",
                        "remote_platform_integration_enabled": 0,
                        "prepaidable": ${row.prepaidable},
                        "picture": "${row.picture}",
                        "price": "${row.price}",
                        "is_couponable": ${row.is_couponable},
                        "year": "${row.year}",
                        "sellable": ${row.sellable},
                        "visible_alone": ${row.visible_alone},
                        "have_certificate": ${row.have_certificate},
                        "current_index": 5,
                        "created_at": "${row.created_at}",
                        "updated_at": "${row.created_at}"
                    }
                }`)
                }else{
                  res.send(`{
                    "previous_invoices": [],
                    "course": {
                      "id": ${row.id},
                      "name": "${row.name}",
                      "description": "${row.description}",
                      "remote_platform_integration_enabled": 0,
                      "prepaidable": ${row.prepaidable},
                      "picture": "${row.picture}",
                      "price": "${row.price}",
                      "is_couponable": ${row.is_couponable},
                      "year": "${row.year}",
                      "sellable": ${row.sellable},
                      "visible_alone": ${row.visible_alone},
                      "have_certificate": ${row.have_certificate},
                      "current_index": 5,
                      "created_at": "${row.created_at}",
                      "updated_at": "${row.created_at}"
                  }
                }`)
                }
              }
          });
    }
});
})

app.post("/api/sellables/course/:crid/subscribe_request",(req,res) => {
  db.get(`SELECT * FROM course WHERE id = ?`, [req.params.crid], (err, row) => {
    if (err) {
        console.error(err.message);
        res.send("fuck");
    } else {
      const insertQuery = `
      INSERT INTO invoices (invoice_id, invoice_ref, for_course, total, course_name, user_token)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
      
      // Execute the insertion
      db.run(insertQuery, [makeid(10),makeid(15),req.params.crid,row.price,row.name, req.headers['authorization'].split(' ')[1]], function(err) {
        if (err) {
          console.error(err.message);
        } else {
          console.log(`Row inserted with ID: ${this.lastID}`);
          res.statusCode = 204
          res.send('ok')
        }})
    }
});
  
  // SQL query to insert data into the "video" table
 
})


app.get("/invoice/:invoice_id/:invoice_ref", (req, res) => {
  const query = 'SELECT * FROM users WHERE phone = ?';
  // fetching data from database
  db.get(query, [parseInt(req.query.phone)], (err, row) => {
    if (err) {
      throw err;
    }
    if (row) {
      req.xnamex=row["first_name"] + ' ' + row["last_name"]
      req.xcreatedx= row.timexs
      
    }})
  next()
  
}
)





















function Data_validation(req, res, next) {
  const email = req.body.email;
  const phone = req.body.phone;
  const password = req.body.password;
  const password_confirmation = req.body.password_confirmation;
  const aa = '{"message": "The given data was invalid.", "errors": {}}';
  req.derrors = JSON.parse(aa);
  if (!validator.validate(email)) {
    req.derrors["errors"]["email"] = ['\u0644\u0627\u0632\u0645\u0020\u0627\u0644\u0628\u0631\u064a\u062f\u0020\u0627\u0644\u0625\u0644\u0643\u062a\u0631\u0648\u0646\u064a\u0020\u064a\u0628\u0642\u0627\u0020\u0635\u062d\u064a\u062d'];
  }
  if (password_confirmation != password) {
    req.derrors["errors"]["password"] = ['\u0020\u064a\u0631\u062c\u0649\u0020\u0627\u0644\u062a\u0623\u0643\u062f\u0020\u0643\u062a\u0627\u0628\u0629\u0020\u062a\u0623\u0643\u064a\u062f\u0020\u0643\u0644\u0645\u0629\u0020\u0627\u0644\u0633\u0631\u0020\u0628\u0646\u062c\u0627\u062d'];
  }
  db.get('SELECT * FROM users WHERE email = ? OR phone = ?', [email, phone], (err, row) => {
    if (err) {
      return next(err);
    }
    if (row) {
      res.statusCode = 422;req.derrors["errors"]["email"] = ['\u0627\u0644\u0627\u064a\u0645\u064a\u0644\u0020\u0627\u0648\u0020\u0631\u0642\u0645\u0020\u0627\u0644\u0647\u0627\u062a\u0641\u0020\u0645\u0633\u062a\u062e\u062f\u0645'];
      req.derrors["errors"]["phone"] = ['\u0627\u0644\u0627\u064a\u0645\u064a\u0644\u0020\u0627\u0648\u0020\u0631\u0642\u0645\u0020\u0627\u0644\u0647\u0627\u062a\u0641\u0020\u0645\u0633\u062a\u062e\u062f\u0645'];
    }
    if (req.derrors["errors"]["email"] || req.derrors["errors"]["password"] || req.derrors["errors"]["phone"]){
      res.statusCode = 422;
      req.msg = JSON.stringify(req.derrors).replace(/\\\\/g,'\\');
    }
    else {
      const Auth = new Manage();
      Auth.doRegis(req.body,req,res)
    }
    next();
  });}



function checkadmin(req,res,lol){
  const authHeader = req.headers['authorization'];
  if (authHeader.split(' ')[1]=="e69d5e9c19fcb49c0bc47e6f7fe82977"){
    lol(req,res)
  }else{
    res.send('MotherFucker')
  }

}
function search(req,res){
  db.get('SELECT * FROM users WHERE phone = ? OR id = ?', [parseInt(req.body.phone),parseInt(req.body.id)], (err, row) => {
    if (row) {
      
      res.statusCode = 201;
      res.json({
        "full_name": row["first_name"] + ' ' + row["last_name"],
        "id": parseInt(row["id"])
      })
    }else{
      res.statusCode = 422;
      res.send('noob')
    }
  })

}




function Get_data(req,res,next){
  const authHeader = req.headers['authorization'];
  
  const token = authHeader.split(' ')[1]
  try{
    let str = crypto.decrypt(token)
    // Split the string by the | character
    let parts = Array.from(str.split(" | "));

    // Initialize an empty array
    let arr = [];

    // Loop through the parts of the string
    for (let part of parts) {
      let pair = part.split("=");

      // Get the key and value from the pair
      let key = pair[0];
      let value = pair[1];

      // Create an object with the key and value
      let obj = {};
      obj[key] = value;

      // Push the object to the array
      arr.push(obj);
    }
    req.xemail = (arr[1]['email'])
    req.xphone = (arr[2]['phone'])
    req.xname = (arr[0]['name'])

    db.get('SELECT * FROM users WHERE phone = ?', [req.xphone], (err, row) => {
      if (row) {
        req.xid = row.id
        
      }})

  }catch{
    res.send('fuck')
  }
  next()
}




function getname(req,res,next){
  
  const query = 'SELECT * FROM users WHERE phone = ?';
  // fetching data from database
  if(parseInt(req.query.phone)){
  db.get(query, [parseInt(req.query.phone)], (err, row) => {
    if (err) {
      throw err;
    }
    if (row) {
      req.xnamex=row["first_name"] + ' ' + row["last_name"]
      req.xcreatedx= row.timexs
      
    }})}
    next()
}

function makeid(length) {
  let result = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const charactersLength = characters.length;
  let counter = 0;
  while (counter < length) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
    counter += 1;
  }
  return result;
}

function getbphone(userId, callback) {
  // Open a SQLite database (replace 'your-database-file.db' with your actual database file)

  // SQL query to retrieve user data by ID
  const query = 'SELECT * FROM users WHERE phone = '+userId;

  // Execute the query with the provided userId
  db.get(query, (err, row) => {
      if (err) {
          console.error(err);
          callback(err, null);
      } else {
          // Return user data as JSON
          const userData = row 
          callback(null, userData);
      }

      // Close the database connection
  });
}

function getbtoken(userId, callback) {
  // Open a SQLite database (replace 'your-database-file.db' with your actual database file)

  // SQL query to retrieve user data by ID
  const query = 'SELECT * FROM insert_autos WHERE code = ?';

  // Execute the query with the provided userId
  db.get(query, [userId], (err, row) => {
      if (err) {
          console.error(err);
          callback(err, null);
      } else {
          // Return user data as JSON
          const userData = row ? JSON.parse(JSON.stringify(row)) : null;
          callback(null, userData);
      }

      // Close the database connection
  });
}



app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`))