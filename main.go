package main

import (
	"WxDump/comm"
	"fmt"
)

func main() {
	wxid := comm.Get_result()
	dbPath := comm.GetFilePath(wxid)
	addrLen := 8
	key, err := comm.GetKey(dbPath, addrLen)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Key:", key)
	}
	comm.CopyMsgDb(dbPath)
	comm.DecryptDb(key)
}
