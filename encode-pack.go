package main

import (
    "encoding/hex"
    "fmt"
    //"os"
	"flag"
)

var (
	result []byte
	encodestr string
)

func main()  {  // 错误，{ 不能在单独的行上

	flag.StringVar(&encodestr, "es", "", "要编码的参数,默认为空")
	flag.Parse()

	if(encodestr!=""){
		result := hexencode(encodestr)
		fmt.Printf("编码结果：%s",result)
	}
}


func hexencode(strvar string) []byte {
	
	src := []byte(strvar)

	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)

	return dst
 }