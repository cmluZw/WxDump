package comm

//V1.0.0
//By cmluZw 2024-08-12

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"os"
	"syscall"
	"unsafe"
)

func patternScanModule(pid uint32, moduleName string, pattern []byte, returnMultiple bool) ([]uintptr, error) {
	hProcess, err := syscall.OpenProcess(0x1F0FFF, false, pid)
	if err != nil {
		return nil, fmt.Errorf("failed to open process: %v", err)
	}
	defer syscall.CloseHandle(hProcess)

	moduleBaseAddress, moduleSize, err := getModuleInfo(pid, moduleName) //返回WeChatWin.dll的基址
	if err != nil {
		return nil, err
	}

	moduleData, err := readProcessMemoryBytes(hProcess, moduleBaseAddress, int(moduleSize)) //读取WeChatWin.dll里的内存
	if err != nil {
		return nil, err
	}

	positions := searchPattern(moduleData, pattern) //在内存中搜索对应模块

	if len(positions) == 0 {
		return nil, nil
	}

	var results []uintptr
	for _, pos := range positions {
		results = append(results, moduleBaseAddress+uintptr(pos)) //返回搜索到的模块的地址
		if !returnMultiple {
			break
		}
	}
	return results, nil
}

func encodeString(s string) []byte {
	return append([]byte(s), 0)
}

//// ReadKeyBytes reads key bytes from a given memory address
//func readKeyBytes(hProcess syscall.Handle, address uintptr, addressLen int) ([]byte, error) {
//	// Create a byte slice to hold the address
//	array := make([]byte, addressLen)
//
//	// Read memory at the given address
//	read := 0
//	ret, _, _ := readProcessMemory.Call(
//		uintptr(hProcess),
//		address,
//		uintptr(unsafe.Pointer(&array[0])),
//		uintptr(addressLen),
//		uintptr(unsafe.Pointer(&read)),
//	)
//	if ret == 0 {
//		return nil, fmt.Errorf("failed to read process memory")
//	}
//
//	// Convert the byte array to an integer address in little-endian format
//	keyAddress := binary.LittleEndian.Uint64(array)
//
//	// Read the key at the new address
//	key := make([]byte, 32)
//	ret, _, _ = readProcessMemory.Call(
//		uintptr(hProcess),
//		uintptr(keyAddress),
//		uintptr(unsafe.Pointer(&key[0])),
//		uintptr(32),
//		uintptr(unsafe.Pointer(&read)),
//	)
//	if ret == 0 {
//		return nil, fmt.Errorf("failed to read process memory")
//	}
//
//	return key, nil
//}

func readKeyBytes(hProcess syscall.Handle, address uintptr, addressLen int) ([]byte, error) {
	array := make([]byte, addressLen)
	read := 0
	ret, _, _ := readProcessMemory.Call(uintptr(hProcess), address, uintptr(unsafe.Pointer(&array[0])), uintptr(addressLen), uintptr(unsafe.Pointer(&read)))
	if ret == 0 {
		return nil, fmt.Errorf("failed to read process memory")
	}
	//address = uintptr(array[0]) 这段代码是原先的，直接调用的是array[0],运行起来key为None,
	address = uintptr(binary.LittleEndian.Uint64(array)) //这行代码将一个字节数组 array 解释为一个 64 位的小端序（little-endian）的无符号整数 (uint64)。
	key := make([]byte, 32)
	ret, _, _ = readProcessMemory.Call(uintptr(hProcess), address, uintptr(unsafe.Pointer(&key[0])), uintptr(32), uintptr(unsafe.Pointer(&read)))
	if ret == 0 {
		return nil, fmt.Errorf("failed to read process memory")
	}
	return key, nil
}

func verifyKey(key []byte, wxDbPath string) bool {
	if wxDbPath == "" || wxDbPath == "none" {
		return true
	}
	const KEY_SIZE = 32
	const DEFAULT_PAGESIZE = 4096
	const DEFAULT_ITER = 64000

	file, err := os.Open(wxDbPath)
	if err != nil {
		return false
	}
	defer file.Close()

	blist := make([]byte, 5000)
	_, err = file.Read(blist)
	if err != nil {
		return false
	}

	salt := blist[:16]
	byteKey := pbkdf2.Key(key, salt, DEFAULT_ITER, KEY_SIZE, sha1.New)
	first := blist[16:DEFAULT_PAGESIZE]

	macSalt := make([]byte, 16)
	for i := range salt {
		macSalt[i] = salt[i] ^ 0x3A
	}
	macKey := pbkdf2.Key(byteKey, macSalt, 2, KEY_SIZE, sha1.New)

	hashMac := hmac.New(sha1.New, macKey)
	hashMac.Write(first[:len(first)-32])
	hashMac.Write([]byte{0x01, 0x00, 0x00, 0x00})

	return hmac.Equal(hashMac.Sum(nil), first[len(first)-32:len(first)-12])
}

func GetKey(dbPath string, addrLen int) (string, error) {
	fmt.Println("正在通过内存读取的形式获取key....")
	process, _ := GetWeChatProcess()
	pid := uint32(process.ProcessID) // 示例进程ID，需要实际的进程ID
	moduleName := "WeChatWin.dll"

	phoneType1 := "iphone\x00"
	phoneType2 := "android\x00"
	phoneType3 := "ipad\x00"

	encodedPhoneType1 := encodeString(phoneType1)
	encodedPhoneType2 := encodeString(phoneType2)
	encodedPhoneType3 := encodeString(phoneType3)

	microMsgPath := fmt.Sprintf("%s\\MSG\\MicroMsg.db", dbPath)

	type1Addrs, err := patternScanModule(pid, moduleName, encodedPhoneType1, true)
	if err != nil {
		return "None", err
	}
	type2Addrs, err := patternScanModule(pid, moduleName, encodedPhoneType2, true)
	if err != nil {
		return "None", err
	}
	type3Addrs, err := patternScanModule(pid, moduleName, encodedPhoneType3, true)
	if err != nil {
		return "None", err
	}

	typeAddrs := type1Addrs
	if len(typeAddrs) < 2 {
		typeAddrs = type2Addrs
	}
	if len(typeAddrs) < 2 {
		typeAddrs = type3Addrs
	}

	if len(typeAddrs) < 2 {
		return "None", nil
	}
	hProcess, err := windows.OpenProcess(0x1F0FFF, false, pid)
	if err != nil {
		return "None", fmt.Errorf("failed to open process: %v", err)
	}
	//defer windows.CloseHandle(hProcess)
	Handle := syscall.Handle(hProcess)
	for i := len(typeAddrs) - 1; i >= 0; i-- { //从后往前遍历
		for j := typeAddrs[i]; j > typeAddrs[i]-2000; j -= uintptr(addrLen) { //从后往前开始，从高地址往低地址，从内存上来说是向下搜索，从搜索出来的基址开始遍历整个基址，遍历2kb，每次步长8kb
			keyBytes, err := readKeyBytes(Handle, j, addrLen) //在搜索出来的基址下面2kb的地方找key
			if err != nil || keyBytes == nil {
				continue
			}
			if dbPath != "None" && verifyKey(keyBytes, microMsgPath) { //验证key通过就是这个key，key和hmackey不一样，HMAC的密钥是刚提到的解密密钥和16字节盐值异或0x3a的值通过PKCS5_PBKF2_HMAC1密钥扩展算法迭代2次计算得到的
				saveKeyToFile(keyBytes, "./key.txt")
				return hex.EncodeToString(keyBytes), nil
			}
		}
	}
	return "None", nil
}

func saveKeyToFile(keyBytes []byte, filePath string) error {
	keyHex := hex.EncodeToString(keyBytes)

	// Write the key to a file
	err := ioutil.WriteFile(filePath, []byte(keyHex), 0644)
	if err != nil {
		return fmt.Errorf("failed to write key to file: %v", err)
	}
	return nil
}

//func main() {
//	wxid := comm.Get_result()
//	filepath := "D:\\weixin\\file\\WeChat Files\\" + string(wxid)
//	dbPath := filepath
//	addrLen := 8
//	key, err := getKey(dbPath, addrLen)
//	if err != nil {
//		fmt.Println("Error:", err)
//	} else {
//		fmt.Println("Key:", key)
//	}
//}
