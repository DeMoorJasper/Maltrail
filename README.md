# Maltrail, modified for easy extendability

This repo is a clone of [Maltrail](https://github.com/stamparm/Maltrail), this clone aims to create a more extendable, simplified, cleaner and advanced version of this amazing IDS.

This clone also includes a cleaner and more modern React/Node.js based web-api/dashboard for going through the logs.

# Getting started

## Installing Maltrail 

```shell
git clone https://github.com/DeMoorJasper/maltrail.git
cd maltrail
```

## Setup sensor

### Installing dependencies

The folder these commands run in doesn't matter.

```shell
sudo apt-get install git python-pcapy
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python get-pip.py
pip install impacket requests
```

### Running sensor

This command assumes you're inside the maltrail folder.

```shell
sudo python sensor.py
```

## Setup webserver

### Installing Node.js

First [Install nvm](https://github.com/creationix/nvm#installation).

Once that's finished install node 8 using `nvm install 8`.

### Install/Build webserver

This command assumes you're inside the maltrail folder and have node installed.

```shell
make build-webserver
```

### Running the webserver

This command assumes you're inside the maltrail folder and have node installed.

```shell
make run-webserver
```

# Documentation

You can mainly find documentation in the original repo for now. [Maltrail](https://github.com/stamparm/Maltrail)

## License

This project is licensed under MIT.

Original Maltrail was written by [`@stamparm`](https://github.com/stamparm)

This clone is written/maintained by [`@DeMoorJasper`](https://github.com/DeMoorJasper)