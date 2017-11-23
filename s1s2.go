package main

import "fmt"
import "./cryptop"

func main() {

	work := ""
	work2 := ""
	fmt.Print("Input string: ")
	fmt.Scanf("%s", &work)
	fmt.Print("Xor against string: ")
	fmt.Scanf("%s", &work2)

	proc1 := cryptop.HexStrToByteArray(work)
	proc2 := cryptop.HexStrToByteArray(work2)

	output,err := cryptop.XorByteArrayToHexString(proc1,proc2)

	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(output)
}
