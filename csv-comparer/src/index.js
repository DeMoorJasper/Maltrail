const path = require('path');

const csv = require('csv');
const fs = require('fs-extra');
const ProgressBar = require('progress');

function readConfig(configLocation) {
  if (!fs.existsSync(configLocation)) {
    throw new Error('Config file:', configLocation, 'could not be found!')
  }

  let config = JSON.parse(fs.readFileSync(configLocation, 'utf8'));

  if (!Array.isArray(config)) {
    throw new Error('Config file has incorrect format.');
  }

  return config;
}

async function compare(inputs, {
  output,
  config
}) {
  console.log("=== MALTRAIL CSV COMPARE TOOL ===");
  console.log('⌛️ Initialising Maltrail CSV comparer');

  inputs = inputs.map(input => path.resolve(input));
  output = path.resolve(output);
  config = path.resolve(config);

  inputs.forEach(input => {
    if (!fs.existsSync(input)) {
      throw new Error('Input file:', input, 'could not be found!')
    }
  });

  if (!fs.existsSync(path.dirname(output))) {
    fs.mkdirpSync(path.dirname(output));
    console.log('✨ Created output directory:', path.dirname(output));
  }

  console.log("⌛️ Reading config file: ", config);
  config = readConfig(config);
  console.log("✨ Config initialised");

  let results = [];
  let inputStreams = [];
  for (let i = 0; i < inputs.length; i++) {
    results[i] = {};
    inputStreams[i] = fs.createReadStream(inputs[i]).pipe(csv.parse({
      delimiter: config[i].seperator
    }));
  }

  let progressBar = new ProgressBar('⌛️ Processing [:bar] :percent, ETA: :etas', {
    complete: '=',
    incomplete: ' ',
    width: 20,
    total: inputs.reduce((accumulator, input) => accumulator + fs.statSync(input).size, 0)
  });

  await Promise.all(
    inputStreams.map((stream, i) => {
      return new Promise((resolve, reject) => {
        stream.on('data', data => {
          progressBar.tick(Buffer.byteLength(data.join(' '), 'utf8'));

          let columnIds = config[i]['column_ids'];

          let label = data[columnIds.LABEL];

          // Skip BENIGN data
          if ((config[i]['benign_label'] && label === config[i]['benign_label']) || !label) {
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

  console.log("\n");

  console.log("✨ Finished processing csv files.");

  fs.writeFileSync(output, JSON.stringify(results, null, '  '));

  console.log("✨ Finished writing results file.");
}

module.exports = compare;
