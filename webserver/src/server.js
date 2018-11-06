const express = require('express');
const bodyParser = require('body-parser');
const database = require('./database/db');
const cors = require('cors');
const config = require('../config.json');
const path = require('path');
const serveStatic = require('serve-static');

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

  let staticFolder = path.join(__dirname, '../../dashboard/dist');
  app.use('/', serveStatic(staticFolder, {
    'index': ['index.html']
  }));

  app.listen(PORT, () => {
    console.log(`Maltrail dashboard listening on http://localhost:${PORT}!`)
  });
})()