package main

import "fmt"
import "./cryptop"
import "encoding/base64"
import "io/ioutil"

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	f,err := ioutil.ReadFile("./7.txt")
	check(err)

	work := make([]byte,base64.StdEncoding.DecodedLen(len(f)))
	_,err = base64.StdEncoding.Decode(work,f)
	check(err)
	fmt.Println(len(f))
	fmt.Println(len(work))
	fmt.Println(string(cryptop.AesEcbDecrypt(work,[]byte("YELLOW SUBMARINE"))))
}
