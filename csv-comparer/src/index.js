const csv = require('csv');
const fs = require('fs');
const path = require('path');

const CONFIG_LOCATION = path.join(__dirname, '../config.json');

async function start() {
  console.log("=== MALTRAIL CSV COMPARE TOOL ===");

  let inputFiles = [];
  let results = [];
  let config = [];

  if (fs.existsSync(CONFIG_LOCATION)) {
    config = JSON.parse(fs.readFileSync(CONFIG_LOCATION, 'utf8'));
  }

  if (!Array.isArray(config)) {
    throw new Error('Config file has incorrect format.');
  }

  console.log("CONFIG READ: ", CONFIG_LOCATION);

  for (let i=0; i < config.length; i++) {
    inputFiles[i] = {};
    results[i] = {};
    inputFiles[i].path = path.join(__dirname, '../input/', config[i].filename);
    inputFiles[i].stream = fs.createReadStream(inputFiles[i].path).pipe(csv.parse({
      delimiter: config[i].seperator
    }));
  }

  console.log("STREAMS INITIALISED!");

  console.log("reading csv files...");
  await Promise.all(
    inputFiles.map((inputFile, i) => {
      return new Promise((resolve, reject) => {
        let stream = inputFile.stream;
        
        stream.on('data', data => {
          let columnIds = config[i]['column_ids'];
          
          let label = data[columnIds.LABEL];
    
          // Skip BENIGN data
          if (config[i]['benign_label'] && label === config[i]['benign_label']) {
            return;
          }
    
          if (!results[i][label]) {
            results[i][label] = {};
          }
    
          let flowId;
          if (columnIds.FLOW_ID !== null) {
            flowId = data[columnIds.FLOW_ID];
          } else {
            flowId = `${data[columnIds.SRC_IP]}-${data[columnIds.DST_IP]}-${data[columnIds.SRC_PORT]}-${data[columnIds.DST_PORT]}`;
          }
      
          if (!results[i][label][flowId]) {
            results[i][label][flowId] = 0;
          }
      
          results[i][label][flowId]++;
        });

        stream.on('end', resolve);
        stream.on('error', reject);
      })
    })
  );

  console.log("=== RESULTS ===");

  for (let i=0; i < config.length; i++) {
    console.log("STREAM:", config[i].name);
    console.log("ATTACK TYPES COUNT:", Object.keys(results[i]).length);
    for (let type of Object.keys(results[i])) {
      console.log(`= ${type} =`);
      for (let flow of Object.keys(results[i][type])) {
        console.log(`${flow}: ${results[i][type][flow]}`);
      }
    }
  }
}

start();
