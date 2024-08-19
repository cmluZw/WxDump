package main

import (
	"WxDump/comm"
	"fmt"
)

func main() {
	var key = ""
	wxid := comm.Get_result()
	dbPath := comm.GetFilePath(wxid)
	addrLen := 8
	is_normal, nickName, account, key_tmp := comm.Get_info()
	if is_normal != true {
		key_tmp, err := comm.GetKey(dbPath, addrLen)
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			fmt.Println("Key:", key_tmp)
		}
		key = key_tmp
	} else {
		fmt.Println("nickName:", nickName)
		fmt.Println("account:", account)
		fmt.Println("Key:", key_tmp)
		key = key_tmp
	}
	comm.CopyMsgDb(dbPath)
	comm.DecryptDb(key)
}
