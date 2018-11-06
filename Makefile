.PHONY: clean run-webserver

clean:
	cd dashboard && npm run clean

run-webserver: clean
	cd dashboard && npm install && npm run build
	cd webserver && npm install && npm run start