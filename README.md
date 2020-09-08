# prom_exporter_auth_log
Exporter for prometheus for checking auth.logs

## Build and start app

go get -d -v ./ 

go build -o bin/main main.go

bin/main

## Build and start app with Docker

docker build -t prometheus_exporter_auth_log . &&  docker run -p 8080:8080 -d prometheus_exporter_auth_log

auth.log example contains here :)

