package main

import (
    "encoding/hex"
    "fmt"
    //"os"
	"flag"
)

var (
	result string
	encodestr string
)

func main()  {  // 错误，{ 不能在单独的行上

	flag.StringVar(&encodestr, "es", "", "要编码的参数,默认为空")
	flag.Parse()

	if(encodestr!=""){
		result := hexencode(encodestr)
		//rs := []rune(result)
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
