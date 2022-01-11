package main

import (
    "encoding/hex"
	"encoding/base64"
	"net/url"
    "fmt"
	//"io/ioutil"
    "os"
	"flag"
)

var (
	result string	
	filepath string
)

func main()  {  // 错误，{ 不能在单独的行上
	// flag.StringVar(&filepath, "f", "", "要编码的文件,默认为空")
	// flag.StringVar(&hexstr, "hexs", "", "要hex编码的参数,默认为空")
	// flag.StringVar(&base64str, "b64s", "", "要base64编码的参数,默认为空")
	// flag.Parse()
	key := "KCQ"

	hexcmd := flag.NewFlagSet("hexcmd", flag.ExitOnError)
    hexstr := hexcmd.String("hexstr", "", "指定hex编码字符串")
    filepath := hexcmd.String("path", "", "指定hex编码文件")


	b64cmd := flag.NewFlagSet("b64cmd", flag.ExitOnError)
    b64str := b64cmd.String("b64str", "", "指定base64编码字符串")
    filepath = b64cmd.String("path", "", "指定base64编码文件")

	urlcmd := flag.NewFlagSet("urlcmd", flag.ExitOnError)
    urlstr := urlcmd.String("urlstr", "", "指定url编码字符串")
    filepath = urlcmd.String("path", "", "指定url编码文件")

	xorcmd := flag.NewFlagSet("xorcmd", flag.ExitOnError)
    xorstr := xorcmd.String("xorstr", "", "指定xor加密字符串")

	_ = filepath

    if len(os.Args) < 2 {
        fmt.Println("hexCmd -hexstr 指定hex编码字符串,-path 指定hex编码文件")
		fmt.Println("b64cmd -b64str 指定base64编码字符串,-path 指定base64编码文件")
		fmt.Println("urlcmd -urlstr 指定url编码字符串,-path 指定url编码文件")
		fmt.Println("xorcmd -xorstr 指定xor加密字符串")
        os.Exit(1)
    }

	switch os.Args[1] {
	case "hexcmd":
        hexcmd.Parse(os.Args[2:])
		result := hexencode(*hexstr)
		fmt.Printf("hex编码结果：%v",result)
	case "b64cmd":
        b64cmd.Parse(os.Args[2:])
		result := b64encode(*b64str)
		fmt.Printf("base64编码结果：%v",result)
	case "urlcmd":
        urlcmd.Parse(os.Args[2:])
		result := urlencode(*urlstr)
		fmt.Printf("url编码结果：%v",result)
	case "xorcmd":
        urlcmd.Parse(os.Args[2:])
		result := xorEncrypt(*xorstr,key)
		fmt.Printf("xor加密结果：%v",result)
	default:
		fmt.Println("hexCmd -hexstr 指定hex编码字符串,-path 指定hex编码文件")
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


//hex编码
func hexencode(strvar string) string {
	
	src := []byte(strvar)

	dst := hex.EncodeToString(src)
	//hex.Encode(dst, src)

	return dst
 }

//b64编码
 func b64encode(strvar string) string{
	sEnc := base64.StdEncoding.EncodeToString([]byte(strvar))
	return sEnc
 }

 //url编码
 func urlencode(strvar string) string{
	escapeUrl := url.QueryEscape(strvar)
	return escapeUrl
 }

//xor加密
func xorEncrypt(input, key string) (output string) {
	for i := 0; i < len(input); i++ {
			output += string(input[i] ^ key[i % len(key)])
	}

	return output
}
