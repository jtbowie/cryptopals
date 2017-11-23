package main

import "fmt"
import "./cryptop"

func main() {
	fmt.Print("Hex string: ")
	work := ""
	fmt.Scanf("%s", &work)

	output := cryptop.Strtobase64(work)

	first := []byte(output[0:4])
	second := []byte(output[4:8])
	fmt.Println(first)
	fmt.Println(second)
	last := make([]byte,len(first))

	for i:=0;i<len(first);i++ {
		last[i] = first[i] ^ second[i]
	}

	fmt.Println(last)
}
