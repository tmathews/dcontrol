export GO111MODULE=off

all: clean build

clean:
	rmdir /S /Q bin
	go clean

build:
	if not exist bin mkdir bin
	go build -ldflags "-s -w" -o .\bin\dctl.exe

.PHONY: build clean all
