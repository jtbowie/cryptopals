package main

import "fmt"
import "./cryptop"

func main() {
	input := ""
	fmt.Scanf("%s", &input)
	work := cryptop.HexStrToByteArray(input)
	val := float64(0)

	test := make([]byte,len(work))
	for i:=0;i<256;i++ {
		test = cryptop.XorSingleByte(work, byte(i))
		val = cryptop.EnglishScore(test)
		if val > 5.5 {
			fmt.Println(fmt.Sprintf("%f",val) + " " + string(test))
		}
	}
}
