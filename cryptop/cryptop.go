package cryptop

import "encoding/hex"
import "encoding/base64"
import "errors"
import "math"
import "bytes"
import "time"
import "unicode"
import "crypto/aes"
import "crypto/rand"
import "strings"
//import "fmt"
import "log"

func HexStrToByteArray(work string) []byte {
	output,err := hex.DecodeString(work)
	if err != nil {
		log.Fatal(err)
	}

	return output
}

func Strtobase64(work string) string {
	store := HexStrToByteArray(work)
	output := base64.StdEncoding.EncodeToString(store)
	return(output)
}

func XorByteArray(first []byte, second []byte) ([]byte, error) {
	if len(first) != len(second) {
		return nil, errors.New("XorByteArray unequal input length")
	}

	output := make([]byte, len(first))

	for i:=0; i<len(first); i++ {
		output[i] = first[i] ^ second[i]
	}

	return output, nil
}

func XorByteArrayToHexString(first []byte, second []byte) (string, error) {
	output,err := XorByteArray(first, second)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(output), nil
}

func EnglishScore(ptxt []byte) float64 {

	exFreqs := map[rune]float64 {
	'a' : 0.0651,
	'b' : 0.0124,
	'c' : 0.0217,
	'd' : 0.0349,
	'e' : 0.1041,
	'f' : 0.0197,
	'g' : 0.0158,
	'h' : 0.0492,
	'i' : 0.0558,
	'j' : 0.0009,
	'k' : 0.0050,
	'l' : 0.0331,
	'm' : 0.0202,
	'n' : 0.0564,
	'o' : 0.0596,
	'p' : 0.0137,
	'q' : 0.0008,
	'r' : 0.0497,
	's' : 0.0515,
	't' : 0.0729,
	'u' : 0.0225,
	'v' : 0.0082,
	'w' : 0.0171,
	'x' : 0.0013,
	'z' : 0.0007,
	' ' : 0.2918 }

	score := float64(0)
	obsv := RuneCounter(ptxt)

	for ch := range obsv {
		if freq, ok := exFreqs[ch]; ok {
			score += math.Pow(obsv[ch]-freq,2.0) * 1.5
		} else {
			score += obsv[ch]
		}
	}

	return score
}

func RuneCounter(rArr []byte) map[rune]float64 {
	output := make(map[rune]float64)
	work := byte(0)
	for i:=0;i<len(rArr);i++ {
		work = byte(unicode.ToLower(rune(rArr[i])))
		output[rune(work)]++
	}

	for ch:= range output {
		output[ch] /= float64(len(rArr))
	}

	return output
}

func XorSingleByte(work []byte, keyc byte) []byte {
	output := make([]byte,len(work))

	for i:=0;i<len(work);i++ {
		output[i] = work[i] ^ keyc
	}

	return output
}

func XorRepeatKey(work []byte, key []byte) []byte {
	out := make([]byte, len(work))
	for i:=0; i<len(work); i++ {
		out[i] = work[i] ^ key[i % len(key)]
	}

	return out
}

func EditDistance(b1 []byte, b2 []byte) uint64 {

	w1 := make([]byte, len(b1))
	w2 := make([]byte, len(b2))
	copy(w1, b1)
	copy(w2, b2)
	count := uint64(0)

	for x:=0;x<len(b1);x++ {
		for i:=0;i<8;i++ {
			if w1[x] & 1 != w2[x] & 1 {
				count++
			}
			w1[x] >>= 1
			w2[x] >>= 1
		}
	}

	return count
}

func AesEcbDecrypt(ct []byte, k []byte) []byte {
	aesBlock,err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}

	bSz := len(ct)
	blSz := len(k)
	blCnt := bSz / blSz
	pt := make([]byte, bSz)

	for y:=0;y<blCnt;y++ {
		aesBlock.Decrypt(pt[y*blSz:blSz*y+blSz],ct[y*blSz:y*blSz+blSz])
	}

	return pt
}

func aesEcbEncrypt(pt []byte, k []byte) []byte {
	aesBlock,err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}

	bSz := len(pt)
	blSz := len(k)
	blCnt := bSz / blSz
	ct := make([]byte,bSz)

	for i:=0;i<blCnt;i++ {
		aesBlock.Encrypt(ct[blSz*i:blSz*i+blSz],pt[blSz*i:blSz*i+blSz])
	}

	return ct
}

func (enc *CbcEncr) CbcEncrypt(pt []byte) ([]byte, error) {
	cipher,err := aes.NewCipher(enc.Key)
	if err != nil {
		return pt,err
	}

	keySz := len(enc.Key)

	if keySz != len(enc.Iv) {
		err = errors.New("CbcEncrypt: len(iv) != len(key)")
		return pt,err
	}

	blockCnt := len(pt) / keySz
	padSz := blockCnt % keySz

	if padSz != 0 {
		blockCnt++
	}

	ct := make([]byte,blockCnt * keySz)
	padPt := make([]byte, blockCnt * keySz)
	copy(padPt, pt)

	nextXor := enc.Iv

	var xorbl []byte
	for i:=0;i<blockCnt;i++ {
		xorbl = XorRepeatKey(nextXor,padPt[keySz*i:keySz*i+keySz])
		cipher.Encrypt(ct[keySz*i:keySz*i+keySz], xorbl)
		nextXor = ct[keySz*i:keySz*i+keySz]
	}

	return ct,nil
}

func (enc *CbcEncr) CbcDecrypt(ct []byte) ([]byte, error) {
	cipher,err := aes.NewCipher(enc.Key)
	if err != nil {
		return ct, errors.New("CbcDecrypt Cipher creation failed")
	}

	blockSz := len(enc.Key)
	bufSz	:= len(ct)
	blockCnt := bufSz / blockSz
	if blockSz != len(enc.Iv) {
		return ct, errors.New("CbcDecrypt key size != iv size")
	}

	if (bufSz % blockCnt) != 0 {
		return ct, errors.New("CbcDecrypt ct not even blocksize")
	}

	pt := make([]byte, bufSz)
	prevXor := make([]byte, blockSz)

	for i:=0;i<blockCnt;i++ {
		cipher.Decrypt(prevXor, ct[blockSz*i:blockSz*i+blockSz])
		if i > 0 {
			prevXor = XorRepeatKey(prevXor, ct[blockSz*(i-1):blockSz*i+blockSz])
			copy(pt[blockSz*i:blockSz*i+blockSz], prevXor)
		} else {
			prevXor = XorRepeatKey(prevXor, enc.Iv)
			copy(pt[:blockSz], prevXor)
		}
	}

	return pt,nil
}

func DetectAesEcb(ctext []byte) bool {
	blockSz := 16
	blockCnt := len(ctext) / blockSz
	work := make(map[string]int)
	for y:=0;y<len(ctext);y+=blockSz {
		work[string(ctext[y:y+blockSz])]++
	}

	if len(work) < blockCnt {
		if blockCnt - len(work) > 1 {
			return true
		}
	}

	return false
}

func PKCS7Pad(b []byte, k int) []byte {
	padSz := k - len(b) % k
	blocks := (len(b) / k) + k
	padBlocks := padSz * blocks
	if padBlocks == 0 {
		padBlocks = len(b) + k
		padSz = k
	}
	output := []byte{}
	output = append(b)
	for i:=0;i<padSz;i++ {
		output = append(output, byte(padSz))
	}
	return output
}

func GenRandAesKey() []byte {
	output := make([]byte, 16)
	rand.Read(output)
	return output
}

func EcbCbcOracle(p []byte) []byte {
	k := GenRandAesKey()
	iv := GenRandAesKey()
	if k[GenSeed() % len(k)] % 2 > 0 {
		return aesEcbEncrypt(p, k)
	} else {
		enc := CbcEncr{k,iv}
		ct,err := enc.CbcEncrypt(p)
		if err != nil {
			panic(err)
		}
		return ct
	}
}

func EcbSingleByteOracle(pt []byte, magick []byte, off int) []byte {
	magickStr := []byte{}
	var err error

	if magick == nil {
		magickStr,err = base64.StdEncoding.DecodeString(ecbmagick)
		if err != nil {
			panic(err)
		}
	}

	magickPt := []byte{}
	if pt != nil {
		if off > 0 {
			magic2d := make([][]byte, 3)
			magic2d[0] = magickStr[0:off]
			magic2d[1] = pt
			magic2d[2] = magickStr[off:]
			magickPt = concatAppend(magic2d)
		} else {
			magickPt = append(pt, magickStr...)
			magickPt = append(magickPt, pt...)
		}
	} else {
		magickPt = append(magickStr)
	}

	keyLen := len(randKey)

	return aesEcbEncrypt(PKCS7Pad(magickPt, keyLen), randKey)
}

func MakeAesEcbDictionary(temp []byte) map[byte][]byte {
	aesKeyMap := make(map[byte][]byte)
	baseStr := make([]byte, len(temp))
	newStr := make([]byte,16)

	copy(baseStr, temp)

	for i:=0;i<256;i++ {
		newStr = append([]byte(baseStr), byte(i))
		aesKeyMap[byte(i)] = aesEcbEncrypt(newStr, randKey)
	}

	return aesKeyMap
}

func FindAesEcbKeyLen(str []byte) int {
	magick  := []byte{}
	preLoad := []byte{}
	opStr	:= []byte{}
	magickLens := []byte{15,16,23,24,31,32}
	var err error

	if str == nil {
		magick,err = base64.StdEncoding.DecodeString(ecbmagick)
		if err != nil {
			panic(err)
		}
	} else {
		copy(magick, str)
	}

	prevBlock := make([]byte, 32)
	block := []byte{}
	preLoad = []byte{byte('A')}

	for i:=0;i<33;i++ {
		if bytes.IndexByte(magickLens, byte(i)) >= 0 {
			opStr = append(preLoad, []byte(magick)...)
			if i % 2 == 0 {
				block = EcbSingleByteOracle(opStr, nil,0)[0:i]
				if bytes.Equal(block[0:i], prevBlock[0:i]) {
					return i
				}
			} else {
				block = EcbSingleByteOracle(opStr, nil,0)[0:i+1]
			}

			copy(prevBlock, block)
		}
		preLoad = append(preLoad, byte('A'))
	}

	return -1
}

func ParseCookie(cook string) map[string]string {

	parCook := strings.Split(cook, "&")
	out := make(map[string]string, len(parCook))
	kv := make([]string, 2)

	for id := range parCook {
		kv = strings.Split(parCook[id], "=")
		out[kv[0]] = kv[1]
	}
	return out
}

func GenProfileByEmail(email string, admin bool) string {
	sep := "&"
	str := "email="
	for ind := range []byte(email) {
		if email[ind] != '&' && email[ind] != '=' {
			str += string(email[ind])
		}
	}

	str += sep + "uid=10"
	if admin {
		str += sep + "role=admin"
	} else {
		str += sep + "role=user"
	}

	return(str)
}

func GenSeed() int {
	return time.Now().Nanosecond()
}

func GenRandBytes(c int) []byte {
	o := make([]byte, c)
	rand.Read(o)
	return o
}

func concatAppend(slices [][]byte) []byte {
    var tmp []byte
    for _, s := range slices {
        tmp = append(tmp, s...)
    }
    return tmp
}

type CbcEncr struct {
	Key []byte
	Iv  []byte
}

var randKey = []byte {48,242,15,144,253,242,27,205,46,91,84,60,143,217,179,44}
const ecbmagick string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
