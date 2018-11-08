.PHONY: clean build-webserver run-webserver

clean:
	cd dashboard && npm run clean

build-webserver: clean
	cd dashboard && npm install && npm run build
	cd webserver && npm install

run-webserver: 
	cd webserver && npm run start