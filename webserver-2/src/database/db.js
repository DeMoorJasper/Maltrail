const sqlite3 = require('sqlite3');
const path = require('path');

// VERBOSE
sqlite3.verbose();

const db = new sqlite3.Database(path.join(process.cwd(), 'events.sqlite'));

let initialised = false;
async function getDB() {
  if (!initialised) {
    await new Promise((resolve, reject) => {
      db.run(`CREATE TABLE IF NOT EXISTS events(
        sensor_name TEXT,
        trail_type TEXT,
        trail TEXT,
        info TEXT,
        reference TEXT,
        accuracy INT,
        severity INT,
        packet_sec INT,
        packet_usec INT,
        packet_data TEXT
      )`, error => {
        if (error) {
          return reject(error);
        }
        resolve();
      });
    });
  
    initialised = true;
  }
  return db;
}

async function insertEvent(event) {
  // TODO: Add event data validator
  return new Promise((resolve, reject) => {
    db.run(`INSERT INTO events (sensor_name, trail_type, trail, info, reference, accuracy, severity, packet_sec, packet_usec, packet_data) 
      VALUES ($sensor_name, $trail_type, $trail, $info, $reference, $accuracy, $severity, $packet_sec, $packet_usec, $packet_data)`, {
        "$sensor_name": event.sensor_name, 
        "$trail_type": event.event_data.trail_type, 
        "$trail": event.event_data.trail, 
        "$info": event.event_data.info, 
        "$reference": event.event_data.reference, 
        "$accuracy": event.event_data.accuracy, 
        "$severity": event.event_data.severity, 
        "$packet_sec": event.event_data.packet.sec, 
        "$packet_usec": event.event_data.packet.usec, 
        "$packet_data": event.event_data.packet.data
      }, (error, rows) => {
      if (error) {
        return reject(error);
      }
      resolve(rows);
    });
  });
}

async function getAllEvents() {
  return new Promise((resolve, reject) => {
    db.all(`SELECT * FROM events`, (error, rows) => {
      if (error) {
        return reject(error);
      }
      resolve(rows);
    });
  });
}

exports.getDB = getDB;
exports.insertEvent = insertEvent;
exports.getAllEvents = getAllEvents;
