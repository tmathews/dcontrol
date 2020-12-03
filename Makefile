export GO111MODULE=off

all: clean linux macos windows

clean:
	rm -rf bin
	go clean

bin:
	mkdir bin

linux: bin
	GOOS=linux GOARCH=amd64 go build -o bin/dctl

macos: bin
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o bin/dctl_macos

windows: bin
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o bin/dctl.exe

.PHONY: clean all linux macos windows
