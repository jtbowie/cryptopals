package main

import "./cryptop"
import "fmt"
import "bytes"

func fixDict(a,b []byte) {
	for i:=0;i<len(b);i++ {
		a[len(a)-len(b)+i] = b[i]
	}
}

func main() {
	keyLen := cryptop.FindAesEcbKeyLen(nil)
	slugSz := keyLen * 2 + 1
	slug := make([]byte, slugSz)
	test := make([]byte, 15)
	for i:=0;i<slugSz;i++ {
		slug[i] = byte('A')
	}
	ct := cryptop.EcbSingleByteOracle(slug, nil,0)
	dictStr := make([]byte, 15)

	myMap := cryptop.MakeAesEcbDictionary(slug[0:15])

	copy(test, slug)
	copy(dictStr, test)
	ct = cryptop.EcbSingleByteOracle(test, nil,0)
	blocks := len(ct) / keyLen
	known := []byte{}
	knownCur := []byte{}
	for y:=0;y<blocks-2;y++ {
		knownCur = nil
		for i:=0;i<keyLen;i++ {
			for ch := range myMap {
				if bytes.Equal(ct[y*keyLen:y*keyLen+keyLen], myMap[ch]) {
					knownCur = append(knownCur,ch)
				}
			}

			if i < 15 {
				ct = cryptop.EcbSingleByteOracle(test[i+1:], nil,y*keyLen)
				fixDict(dictStr, knownCur)
				myMap = cryptop.MakeAesEcbDictionary(dictStr)
			} else {
				ct = cryptop.EcbSingleByteOracle(nil, nil,y*keyLen)
				myMap = cryptop.MakeAesEcbDictionary(knownCur)
				for ch := range myMap {
					if bytes.Equal(ct[y*keyLen:y*keyLen+keyLen], myMap[ch]) {
						knownCur = append(knownCur, ch)
					}
				}
				if (y == blocks - 3) {
					break
				}
				copy(dictStr, slug)
				myMap = cryptop.MakeAesEcbDictionary(dictStr)
				ct = cryptop.EcbSingleByteOracle(test, nil, y*keyLen+keyLen)
			}
		}
		known = append(known, knownCur...)
	}
	fmt.Println(string(known),len(known))
}
