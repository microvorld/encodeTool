package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	rsarand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"time"
	"unsafe"

	"github.com/google/uuid"
)

const (
	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	// 6 bits to represent a letter index
	letterIdBits = 6
	// All 1-bits as many as letterIdBits
	letterIdMask = 1<<letterIdBits - 1
	letterIdMax  = 63 / letterIdBits
)

var (
	result    string
	hexpath   string
	b64path   string
	xorpath   string
	uuidspath string
	src       = rand.NewSource(time.Now().UnixNano())
	n         = 4
)

func init() {
}

func main() { // 错误，{ 不能在单独的行上
	// flag.StringVar(&filepath, "f", "", "要编码的文件,默认为空")
	// flag.StringVar(&hexstr, "hexs", "", "要hex编码的参数,默认为空")
	// flag.StringVar(&base64str, "b64s", "", "要base64编码的参数,默认为空")
	// flag.Parse()
	hexcmd := flag.NewFlagSet("hexcmd", flag.ExitOnError)
	hexstr := hexcmd.String("hexstr", "", "指定hex编码字符串")
	hexpath := hexcmd.String("path", "", "指定hex编码文件")

	b64cmd := flag.NewFlagSet("b64cmd", flag.ExitOnError)
	b64str := b64cmd.String("b64str", "", "指定base64编码字符串")
	b64path := b64cmd.String("path", "", "指定base64编码文件")

	urlcmd := flag.NewFlagSet("urlcmd", flag.ExitOnError)
	urlstr := urlcmd.String("urlstr", "", "指定url编码字符串")

	xorcmd := flag.NewFlagSet("xorcmd", flag.ExitOnError)
	xorstr := xorcmd.String("xorstr", "", "指定xor加密字符串")
	xorpath := xorcmd.String("path", "", "指定xor加密文件")

	uuidcmd := flag.NewFlagSet("uuidcmd", flag.ExitOnError)
	uuidspath := uuidcmd.String("path", "", "指定将目标文件转为uuid格式文件")

	rsacmd := flag.NewFlagSet("rsacmd", flag.ExitOnError)
	rsastr := rsacmd.String("rsastr", "", "指定rsa加密字符串")
	rsapath := rsacmd.String("path", "", "指定rsa加密文件")

	aescmd := flag.NewFlagSet("aescmd", flag.ExitOnError)
	aesstr := aescmd.String("aesstr", "", "指定aes加密字符串")
	aespath := aescmd.String("path", "", "指定aes加密文件")
	//_ = filepath

	if len(os.Args) < 2 {
		// fmt.Println("hexcmd -hexstr 指定hex编码字符串,-path 指定hex编码文件")
		// fmt.Println("b64cmd -b64str 指定base64编码字符串,-path 指定base64编码文件")
		// fmt.Println("urlcmd -urlstr 指定url编码字符串")
		// fmt.Println("xorcmd -xorstr 指定xor加密字符串,-path 指定xor加密文件")
		// fmt.Println("uuidcmd -path 指定uuid编码文件")
		// fmt.Println("xorcmd -xorstr 指定xor加密字符串,-path 指定xor加密文件")
		os.Exit(1)
	}

	switch os.Args[1] {
	//hex编码
	case "hexcmd":
		hexcmd.Parse(os.Args[2:])
		if *hexpath != "" {
			result := hexencode(readfile(*hexpath))
			fmt.Printf("hex编码结果：%v", result)
		} else if *hexstr != "" {
			result := hexencode([]byte(*hexstr))
			fmt.Printf("hex编码结果：%v", result)
		}
		//base64编码
	case "b64cmd":
		b64cmd.Parse(os.Args[2:])
		if *b64path != "" {
			result := b64encode(readfile(*b64path))
			fmt.Printf("base64编码结果：%v", result)
		} else if *b64str != "" {
			result := b64encode([]byte(*b64str))
			fmt.Printf("base64编码结果：%v", result)
		}
		//url编码
	case "urlcmd":
		urlcmd.Parse(os.Args[2:])
		result := urlencode(*urlstr)
		fmt.Printf("url编码结果：%v", result)
		//xor加密
	case "xorcmd":
		xorcmd.Parse(os.Args[2:])
		key := xorkeygenerate()
		fmt.Printf("xor密钥：%v\n", key)

		if *xorpath != "" {
			result := xorEncrypt((readfile(*xorpath)), []byte(key))
			fmt.Printf("xor加密结果：%v", result)
		} else if *xorstr != "" {
			result := xorEncrypt([]byte(*xorstr), []byte(key))
			fmt.Printf("xor加密结果：%v", result)
		}
		//uuid编码
	case "uuidcmd":
		uuidcmd.Parse(os.Args[2:])
		if *uuidspath != "" {
			uuid_generate(*uuidspath)
		}
		//rsa加密
	case "rsacmd":
		rsacmd.Parse(os.Args[2:])
		prvKey, pubKey := GenRsaKey()
		fmt.Println(string(prvKey))
		fmt.Println(string(pubKey))

		if *rsapath != "" {
			result := RsaEncrypt((readfile(*rsapath)), pubKey)
			finalresult := base64.StdEncoding.EncodeToString(result)
			//text := RsaDecrypt(finalresult, prvKey)

			fmt.Printf("rsa加密结果：%v\n", finalresult)
			//fmt.Printf("rsa解密结果：\n%v", )
		} else if *rsastr != "" {
			result := RsaEncrypt([]byte(*rsastr), pubKey)
			fmt.Printf("rsa加密结果：%v", base64.StdEncoding.EncodeToString(result))
		}
		//aes加密
	case "aescmd":
		aescmd.Parse(os.Args[2:])

		if *aespath != "" {
			EncryptWithAes((readfile(*aespath)))
		} else if *aesstr != "" {
			EncryptWithAes([]byte(*aesstr))
		}
	default:
		fmt.Println("hexcmd -hexstr 指定hex编码字符串,-path 指定hex编码文件")
		fmt.Println("b64cmd -b64str 指定base64编码字符串,-path 指定base64编码文件")
		fmt.Println("urlcmd -urlstr 指定url编码字符串,-path 指定url编码文件")
		fmt.Println("xorcmd -xorstr 指定xor加密字符串")
		fmt.Println("uuidcmd -path 指定uuid编码文件")
		fmt.Println("rsacmd -rsastr 指定rsa加密字符串,-path 指定rsa加密文件")
		fmt.Println("aescmd -aesstr 指定aes加密字符串,-path 指定aes加密文件")
		os.Exit(1)
	}
	// if(hexstr!=""){
	// 	result := hexencode(hexstr)
	// 	//rs := []rune(result)
	// 	fmt.Printf("编码结果：%v",result)
	// }else if (base64str!="") {
	// 	fmt.Printf("编码结果：%v",result)
	// }

}

//读文件
func readfile(filepath string) []byte {
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		panic(err)
	}
	return content
}

//hex编码
func hexencode(strvar []byte) string {

	src := strvar
	dst := hex.EncodeToString(src)
	//hex.Encode(dst, src)

	return dst
}

//b64编码
func b64encode(strvar []byte) string {
	sEnc := base64.StdEncoding.EncodeToString(strvar)
	return sEnc
}

//url编码
func urlencode(strvar string) string {
	escapeUrl := url.QueryEscape(strvar)
	return escapeUrl
}

//xor加密
func xorEncrypt(input, key []byte) (output string) {
	var finalresult []byte = make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		finalresult[i] = (input[i] ^ key[0] ^ key[2] ^ key[1] ^ key[3])
	}
	output = hexencode(finalresult)

	return output
}

//xor随机密钥生成
func xorkeygenerate() string {

	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdMax letters!
	for i, cache, remain := n-1, src.Int63(), letterIdMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdMax
		}
		if idx := int(cache & letterIdMask); idx < len(letters) {
			b[i] = letters[idx]
			i--
		}
		cache >>= letterIdBits
		remain--
	}
	return *(*string)(unsafe.Pointer(&b))
}

//uuid生成
func shellcode_to_uuids(shellcode []byte) ([]string, error) {
	// Pad shellcode to 16 bytes, the size of a UUID
	if len(shellcode)%16 != 0 {
		pad := bytes.Repeat([]byte{byte(0x90)}, 16-len(shellcode)%16)
		shellcode = append(shellcode, pad...)
	}

	var uuids []string

	for i := 0; i < len(shellcode); i += 16 {
		var uuidBytes []byte

		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, binary.BigEndian.Uint32(shellcode[i:i+4]))
		uuidBytes = append(uuidBytes, buf...)

		// Add next 2 bytes
		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(shellcode[i+4:i+6]))
		uuidBytes = append(uuidBytes, buf...)

		// Add next 2 bytes
		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(shellcode[i+6:i+8]))
		uuidBytes = append(uuidBytes, buf...)

		// Add remaining
		uuidBytes = append(uuidBytes, shellcode[i+8:i+16]...)

		u, err := uuid.FromBytes(uuidBytes)
		if err != nil {
			return nil, fmt.Errorf("there was an error converting bytes into a UUID:\n%s", err)
		}

		uuids = append(uuids, u.String())
	}
	return uuids, nil
}

func uuid_generate(srcpath string) {
	uuids, _ := shellcode_to_uuids(readfile(srcpath))
	var despath = "uuid.txt"
	file, err := os.OpenFile(despath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("文件打开失败", err)
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	for _, i := range uuids {
		write.WriteString("\"" + i + "\"" + ",")
	}
	//Flush将缓存的文件真正写入到文件中
	write.Flush()
	fmt.Printf("生成文件名：%v", despath)

}

/*************************rsa加密*************************/
//参考：https://cloud.tencent.com/developer/article/1475706
//RSA公钥私钥产生
func GenRsaKey() (prvkey, pubkey []byte) {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rsarand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	prvkey = pem.EncodeToMemory(block)
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	pubkey = pem.EncodeToMemory(block)
	return
}

// 公钥加密
func RsaEncrypt(data, keyBytes []byte) []byte {
	//解密pem格式的公钥
	partLen := 128 - 11
	chunks := split(data, partLen)

	buffer := bytes.NewBuffer([]byte{})

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(errors.New("public key error"))
	}
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//加密
	//ciphertext, err := rsa.EncryptPKCS1v15(rsarand.Reader, pub, data)
	for _, chunk := range chunks {
		bytes, err := rsa.EncryptPKCS1v15(rsarand.Reader, pub, chunk)
		if err != nil {
			panic(err)
		}
		buffer.Write(bytes)
	}
	if err != nil {
		panic(err)
	}
	//return ciphertext
	return buffer.Bytes()
}

// // 私钥解密
// func RsaDecrypt(ciphertext string, keyBytes []byte) []byte {
// 	partLen := 128
// 	raw, err := base64.StdEncoding.DecodeString(ciphertext)
// 	chunks := split(raw, partLen)

// 	//获取私钥
// 	block, _ := pem.Decode(keyBytes)
// 	if block == nil {
// 		panic(errors.New("private key error!"))
// 	}
// 	//解析PKCS1格式的私钥
// 	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
// 	if err != nil {
// 		panic(err)
// 	}
// 	// 解密
// 	// data, err := rsa.DecryptPKCS1v15(rsarand.Reader, priv, ciphertext)
// 	// if err != nil {
// 	// 	panic(err)
// 	// }
// 	buffer := bytes.NewBuffer([]byte{})
// 	for _, chunk := range chunks {
// 		decrypted, err := rsa.DecryptPKCS1v15(rsarand.Reader, priv, chunk)
// 		if err != nil {
// 			panic(err)
// 		}
// 		buffer.Write(decrypted)
// 	}

// 	return buffer.Bytes()
// }

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}

/*************************rsa加密*************************/

/*aes加密，密钥为时间戳的md5值，再将md5值hexdecode*/
func md5V(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

//
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//AesEncrypt 加密函数
func AesEncrypt(plaintext []byte, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	plaintext = PKCS7Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(plaintext))
	blockMode.CryptBlocks(crypted, plaintext)
	return crypted, nil
}

// AesDecrypt 解密函数
// func AesDecrypt(ciphertext []byte, key, iv []byte) ([]byte, error) {
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	blockSize := block.BlockSize()
// 	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
// 	origData := make([]byte, len(ciphertext))
// 	blockMode.CryptBlocks(origData, ciphertext)
// 	origData = PKCS7UnPadding(origData)
// 	return origData, nil
// }

func EncryptWithAes(input []byte) {
	seed := strconv.FormatInt(time.Now().UnixNano(), 10)
	md5Str := md5V(seed)
	key, _ := hex.DecodeString(md5Str)
	//fmt.Printf("时间戳：%v\n", seed)
	fmt.Printf("密钥(hexdecode it)：%v\n", md5Str)
	content := input

	c := make([]byte, aes.BlockSize+len(content))
	iv := c[:aes.BlockSize]

	//加密
	ciphertext, err := AesEncrypt(content, key, iv)
	if err != nil {
		panic(err)
	}

	//打印加密base64后密码
	fmt.Printf("AES加密结果：%v", base64.StdEncoding.EncodeToString(ciphertext))
}

/*************************aes加密*************************/
