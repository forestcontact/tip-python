package main

import (
	"fmt"
)

func main() {
	_, err := PrivateKeyFromBytes([]byte{})
	fmt.Printf("hello,world, %v\n", err)
}
