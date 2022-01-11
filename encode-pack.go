package main

import (
    "encoding/hex"
    "fmt"
    //"os"
	"flag"
)

var (
	result string
	hexstr string
	base64str string
)

func main()  {  // 错误，{ 不能在单独的行上

	flag.StringVar(&hexstr, "hexs", "", "要hex编码的参数,默认为空")
	flag.StringVar(&base64str, "b64s", "", "要base64编码的参数,默认为空")
	flag.Parse()

	if(hexstr!=""){
		result := hexencode(hexstr)
		//rs := []rune(result)
		fmt.Printf("编码结果：%v",result)
	}else if (base64str!="") {
		fmt.Printf("编码结果：%v",result)
	}

}


//hex编码
func hexencode(strvar string) string {
	
	src := []byte(strvar)

	dst := hex.EncodeToString(src)
	//hex.Encode(dst, src)

	return dst
 }
