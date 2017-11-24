package main

import "fmt"
import "./cryptop"

func main() {
	input1 := []byte("this is a test")
	input2 := []byte("wokka wokka!!!")

	fmt.Println(cryptop.EditDistance(input1,input2))
}
