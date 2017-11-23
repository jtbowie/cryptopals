package main

import "fmt"
import "./cryptop"

func main() {
	fmt.Print("Hex string: ")
	work := ""
	fmt.Scanf("%s", &work)

	fmt.Println(cryptop.Strtobase64(work))
}
