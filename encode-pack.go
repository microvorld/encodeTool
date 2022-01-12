package main

import (
    "encoding/hex"
    "encoding/base64"
    "net/url"
    "fmt"
    "io/ioutil"
    "os"
    "flag"
    //"github.com/google/uuid"
	"math/rand"
	"time"
	"unsafe"
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
	result string
	hexpath string
	b64path string
	xorpath string
	src = rand.NewSource(time.Now().UnixNano())
    n = 4
)

func init(){
}

func main()  {  // 错误，{ 不能在单独的行上
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

	//_ = filepath

    if len(os.Args) < 2 {
        fmt.Println("hexcmd -hexstr 指定hex编码字符串,-path 指定hex编码文件")
		fmt.Println("b64cmd -b64str 指定base64编码字符串,-path 指定base64编码文件")
		fmt.Println("urlcmd -urlstr 指定url编码字符串")
		fmt.Println("xorcmd -xorstr 指定xor加密字符串,-path 指定xor加密文件",)
        os.Exit(1)
    }


	switch os.Args[1] {
	case "hexcmd":
        hexcmd.Parse(os.Args[2:])
		if(*hexpath!=""){
			result := hexencode(readfile(*hexpath))
			fmt.Printf("hex编码结果：%v",result)
		}else if(*hexstr!=""){
		result := hexencode([]byte(*hexstr))
		fmt.Printf("hex编码结果：%v",result)
		}
	case "b64cmd":
        b64cmd.Parse(os.Args[2:])
		if(*b64path!=""){
			result := b64encode(readfile(*b64path))
			fmt.Printf("base64编码结果：%v",result)
		}else if(*b64str!=""){
		result := b64encode([]byte(*b64str))
		fmt.Printf("base64编码结果：%v",result)
		}
	case "urlcmd":
        urlcmd.Parse(os.Args[2:])
		result := urlencode(*urlstr)
		fmt.Printf("url编码结果：%v",result)
	case "xorcmd":
        xorcmd.Parse(os.Args[2:])
		key := xorkeygenerate()
		fmt.Printf("xor密钥：%v\n",key)

		if(*xorpath!=""){
			result := xorEncrypt((readfile(*xorpath)),[]byte(key))
			fmt.Printf("xor加密结果：%v",result)
		}else if(*xorstr!=""){
		result := xorEncrypt([]byte(*xorstr),[]byte(key))
		fmt.Printf("xor加密结果：%v",result)
		}
	default:
		fmt.Println("hexcmd -hexstr 指定hex编码字符串,-path 指定hex编码文件")
		fmt.Println("b64cmd -b64str 指定base64编码字符串,-path 指定base64编码文件")
		fmt.Println("urlcmd -urlstr 指定url编码字符串,-path 指定url编码文件")
		fmt.Println("xorcmd -xorstr 指定xor加密字符串")
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
func readfile(filepath string) []byte{
	content ,err :=ioutil.ReadFile(filepath)
	if err !=nil {
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
 func b64encode(strvar []byte) string{
	sEnc := base64.StdEncoding.EncodeToString(strvar)
	return sEnc
 }

 //url编码
 func urlencode(strvar string) string{
	escapeUrl := url.QueryEscape(strvar)
	return escapeUrl
 }

//xor加密
func xorEncrypt(input, key []byte) (output string) {
	var finalresult []byte = make([]byte, len(input))
	for i := 0; i < len(input); i++ {
			finalresult[i] = (input[i] ^ key[0]^key[2]^key[1]^key[3])
	}
	output = hexencode(finalresult)

	return output
}

//xor随机密钥生成
func xorkeygenerate() string{

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
