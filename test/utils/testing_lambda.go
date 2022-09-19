package main

import (
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
)

func HandleRequest() {
	fmt.Println("e2eTest run")
}

func main() {
	lambda.Start(HandleRequest)
}
