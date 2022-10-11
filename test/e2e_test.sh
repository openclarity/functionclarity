#!/usr/bin/env bash
echo "starting..."
cd ./aws_function_pkg
go build
mv ./aws_function_pkg ../test/aws_function
echo "aws_function binary copied to test folder"

cd ../test/utils
go build testing_lambda.go
echo "testing lambda built successfully"

cd ../..
cp ./run_env/utils/unified-template.template ./test/
echo "stack template copied to test folder"

echo "e2e tests started"
cd ./test
go test -timeout 30m -v ./...
