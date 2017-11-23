package main

import "fmt"
import "encoding/hex"
import "io/ioutil"
import "./cryptop"

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	str := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := []byte("ICE")
	encstr := cryptop.XorRepeatKey([]byte(str), key)
	fmt.Println(hex.EncodeToString(encstr))
	outstr := string(cryptop.XorRepeatKey(encstr,key))
	fmt.Println(outstr)

	ptext,err := ioutil.ReadFile("./encryptme")
	check(err)
	fmt.Println(hex.EncodeToString(ptext))
}

