package main

import "fmt"
import "./cryptop"

func main() {
	str := "YELLOW SUBMARINEYELLOW SUBMARINE"
	ct := cryptop.EcbCbcOracle([]byte(str))
	k := cryptop.GenRandAesKey()

	fmt.Println(ct)
	fmt.Println(cryptop.DetectAesEcb(ct))
	fmt.Println(k)
}
