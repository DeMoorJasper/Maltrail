const express = require('express');
const bodyParser = require('body-parser');
const database = require('./database/db');
const xss = require('xss');

const PORT = 3000;

(async function start() {
  const app = express();

  console.log("Initialising DB");
  
  await database.getDB();

  console.log("DB initialised!");

  app.use(bodyParser.json({
    type: 'application/*+json'
  }));

  app.use(bodyParser.urlencoded({
    extended: true
  }));

  app.get('/', async (req, res) => {
    res.header("Content-Type", "text/html");

    try {
      let events = await database.getAllEvents();
      res.status(200);
      res.write(`<h1>=== RECORDED EVENTS ===</h1>`);
      if (events) {
        let count = 0;
        for (let event of events) {
          let fields = ["sensor_name", "trail_type", "trail", "info", "reference", "accuracy", "severity", "packet_sec", "packet_usec", "packet_data"];
          res.write(`<h2>EVENT #${count}:</h2>`);
          for (let field of fields) {
            res.write('<ul>');
            res.write(`<li>${field}: ${xss(event[field])}</li>`);
            res.write('</ul>');
          }
          count++;
        }
        res.end(`<p>Total amount of events: ${events.length}</p>`);
      } else {
        res.end('<p>No events found!</p>');
      }
    } catch(e) {
      console.error(e);
      res.status(500);
      return res.send('An error occured!');
    }
  });

  app.post('/add_packet', async (req, res) => {
    let body = req.body;
    if (body.json) {
      try {
        data = JSON.parse(body.json);

        await database.insertEvent(data);

        console.log('Event added to the database!');
      } catch(e) {
        console.error(e);
        return res.send(500, "Invalid JSON!");
      }
    }
    
    res.send("OK");
  });

  app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}!`)
  });
})()