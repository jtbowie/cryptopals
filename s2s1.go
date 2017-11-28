package main

import "fmt"
import "./cryptop"
import "io/ioutil"
import "encoding/base64"

func main() {
	str := "YELLOW SUBMARINE"
	iv := make([]byte,16)
	for i:=0;i<len(str);i++ {
		iv[i] = 0
	}

	f,_ := ioutil.ReadFile("./10.txt")

	ct := make([]byte,base64.StdEncoding.DecodedLen(len(f)))
	_,err := base64.StdEncoding.Decode(ct,f)
	if err != nil {
		panic(err)
	}

	fmt.Println(len(ct))
	cbc := cryptop.CbcEncr{[]byte(str),iv}
	out,err := cbc.CbcDecrypt(ct)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
