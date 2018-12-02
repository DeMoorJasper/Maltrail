# Maltrail, modified for easy extendability

This repo is a fork of [Maltrail](https://github.com/stamparm/Maltrail), this fork aims to create a more extendable, simplified, cleaner and advanced version of Maltrail.

This fork also includes a cleaner and more modern React/Node.js based web-api/dashboard for going through the logs.

# Getting started

## Installing Maltrail 

```shell
git clone https://github.com/DeMoorJasper/maltrail.git
cd maltrail
```

## Setup sensor

### Installing dependencies

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

For the basic functionality you can find some documentation in the original repo: [Maltrail](https://github.com/stamparm/Maltrail). However this is slightly outdated and this fork is lacking features that the original project had and vice versa.

For the plugin/trigger functionality there is no documentation at the moment other than the existing (example) plugins and triggers.

# Contributing

We welcome any contributor, especially on the plugin side.

The goal of this project is to be a powerful IDS out of the box that is super extendable so it can be used in more extensive research and practise.

If you're intrested known work and bugs are listed in the issues section. Feel free to check it out, ask questions and hopefully try to implement/fix it with a PR.

## License

This project is licensed under MIT.

Original Maltrail was written by [`@stamparm`](https://github.com/stamparm)

This fork is written/maintained by [`@DeMoorJasper`](https://github.com/DeMoorJasper)
