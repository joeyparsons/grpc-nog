#!/bin/bash
mkdir -p bin
go build -v -a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo -o bin/auth-admin ./auth-admin
go build -v -a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo -o bin/auth-client ./auth-client
go build -v -a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo -o bin/auth-server ./auth-server
go build -a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo -o bin/nog-client ./nog-client
go build -a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo -o bin/nog-server ./nog-server
