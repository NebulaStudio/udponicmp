all:
	go build -ldflags "-s -w" -v -trimpath -o bin/kcponicmp

bpf:
	go build -ldflags "-s -w" -v -trimpath -tags bpf -o bin/kcponicmp
