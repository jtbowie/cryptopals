package main

import "fmt"
import "./cryptop"
import "encoding/hex"
import "io/ioutil"
import "strings"

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	f,err := ioutil.ReadFile("./8.txt")
	check(err)
	work := strings.Split(string(f),"\n")
	val := 0

	for y:=0;y<len(work);y++ {
		decoded,err := hex.DecodeString(work[y])
		check(err)

		val = cryptop.DetectAesEcb(decoded)
		if val > 0 {
			fmt.Println(work[y])
		}
	}
}
