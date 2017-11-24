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
	f,err := ioutil.ReadFile("./6.txt")
	check(err)
	fbytes,err := base64.StdEncoding.DecodeString(string(f))
	check(err)
	editmap := make(map[uint64]float64)
	b := make([][]byte, 4)
	editdist := uint64(0)
	for i:=uint64(2);i<41;i++ {
		editdist = 0
		b[0] = fbytes[:i]
		b[1] = fbytes[i:i*2]
		b[2] = fbytes[i*2:i*3]
		b[3] = fbytes[i*3:i*4]

		editdist += cryptop.EditDistance(b[0],b[1])
		editdist += cryptop.EditDistance(b[1],b[2])
		editdist += cryptop.EditDistance(b[2],b[3])
		editmap[i] = float64(editdist) / float64(i * 3)
	}

	for y := range editmap {
		if editmap[y] < 3 {
			fmt.Printf("%f %d\n", editmap[y], y)
		}
	}

	keySz := 29
	workArrSz := len(fbytes) / keySz
	workArr := make([][]byte,workArrSz+1)
	transArr := make([][]byte,keySz)

	for i:=0;i<len(workArr);i++ {
		workArr[i] = fbytes[i*keySz:i*keySz+keySz]
	}

	fmt.Println(workArr[:][0])
	for y:=0;y<len(transArr);y++ {
		transArr[y] = make([]byte,workArrSz)
		for i:=0;i<workArrSz;i++ {
			transArr[y][i] = workArr[i][y]
		}
	}
	score := float64(0)
	key := make([]byte,keySz)
	for i:=0;i<len(transArr);i++ {
		for x:=0;x<255;x++ {
			res := cryptop.XorSingleByte(transArr[i],byte(x))
			score = cryptop.EnglishScore(res) / float64(len(transArr[1]))
			score *= 1000
			if score < 2.5 {
			//	fmt.Println(string(res),score,x)
				key[i] = byte(x)
			}
		}
	}

	fmt.Println(string(key))
	fmt.Println(string(cryptop.XorRepeatKey(fbytes,key)))
}
