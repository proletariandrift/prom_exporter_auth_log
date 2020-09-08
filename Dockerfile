FROM golang:latest

WORKDIR /go/src/app

COPY . .

ENV LOG_PATH /go/src/app

RUN go get -d -v ./
RUN go build -o bin/main main.go
CMD ["bin/main"]
