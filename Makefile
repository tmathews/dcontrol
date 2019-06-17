all: clean linux macos win

clean:
	rm -rf bin
	go clean

bin:
	mkdir bin

linux: bin
	GOOS=linux GOARCH=amd64 go build -o bin/dcontrol

macos: bin
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o bin/dcontrol-macos

win: bin
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o bin/dcontrol-win
