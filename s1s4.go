package main

import "fmt"
import "io/ioutil"
import "strings"
import "./cryptop"

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	data,err := ioutil.ReadFile("./4.txt")
	check(err)

	workArr := strings.Split(string(data), "\n")

	work := make([]byte,len(workArr[0]))
	test := make([]byte,len(workArr[0]))
	val := float64(0)

	for i:=0;i<len(workArr);i++{
		work = cryptop.HexStrToByteArray(strings.ToLower(string(workArr[i])))
		for x:=0;x<256;x++ {
			test = cryptop.XorSingleByte(work,byte(x))
			val = cryptop.EnglishScore(test)
			if val < 2.75 {
				if val > 1 {
					fmt.Printf("%f 0x%x\n", val, x)
				}
			}
		}
	}
}
