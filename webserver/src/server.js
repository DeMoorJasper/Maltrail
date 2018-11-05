const express = require('express');
const bodyParser = require('body-parser');
const database = require('./database/db');
const xss = require('xss');
const cors = require('cors');
const config = require('../config.json');

const PORT = process.env.PORT || config.PORT || 3000;

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

  app.use(cors({
    origin: '*'
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
          res.write(`<h2>EVENT #${count}:</h2>`);
          for (let field of Object.keys(event)) {
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

  app.get('/events', async (req, res) => {
    res.header("Content-Type", "application/json");

    // TODO: Support filtering
    try {
      let events = await database.getAllEvents();
      res.status(200);
      res.send(events);
    } catch(e) {
      console.error(e);
      res.status(500);
      return res.send('An error occured!');
    }
  });

  app.post('/add_packet', async (req, res) => {
    // TODO: Validate data and add some kind of sensor whitelist to disallow any malicious data
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