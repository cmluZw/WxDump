package comm

//V1.0.0
//By cmluZw 2024-08-12

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// 获取微信文件路径
func GetFilePath(wxid string) string {
	wDir := "MyDocument:"
	isWDir := false

	if wxid == "" {
		return "None"
	}

	// 尝试从注册表获取微信路径
	if runtime.GOOS == "windows" {
		key, err := OpenKey(syscall.HKEY_CURRENT_USER, `Software\Tencent\WeChat`, syscall.KEY_READ)
		if err == nil {
			defer CloseKey(key)
			value, err := QueryValueEx(key, "FileSavePath") //这是找出是否修改过文件路径，比如我这里就是D:\weixin\file，没修改过这里就是MyDocument
			if err == nil {                                 //从注册表中找出路径
				wDir = value
				isWDir = true
			}
		}
	}

	// 如果没有找到路径，尝试从环境变量获取
	if !isWDir {
		userProfile := os.Getenv("USERPROFILE")
		path3ebffe94 := filepath.Join(userProfile, "AppData", "Roaming", "Tencent", "WeChat", "All Users", "config", "3ebffe94.ini") //这个文件是直接存储微信路径的配置文件
		wDir = readFile(path3ebffe94)
		if wDir != "" {
			isWDir = true
		}
	}

	// 如果仍然没有找到路径，尝试从用户文档路径获取
	if wDir == "MyDocument:" {
		documentsPath := os.Getenv("USERPROFILE")
		wDir = filepath.Join(documentsPath, "Documents")
	}

	msgDir := filepath.Join(wDir, "WeChat Files")

	s, _ := os.Stat(msgDir)
	if wxid == "all" && s.IsDir() {
		return msgDir
	}

	filePath := filepath.Join(msgDir, wxid)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "None"
	}
	return filePath

}

//注册表操作

// 定义一个结构体来模拟Python中的字典
type RegistryKey struct {
	handle syscall.Handle
}

// 定义一个函数来打开注册表键
func OpenKey(root syscall.Handle, path string, access uint32) (*RegistryKey, error) {
	var key syscall.Handle
	err := syscall.RegOpenKeyEx(root, syscall.StringToUTF16Ptr(path), 0, access, &key)
	if err != nil {
		return nil, err
	}
	return &RegistryKey{handle: key}, nil
}

// 定义一个函数来查询注册表值
func QueryValueEx(key *RegistryKey, valueName string) (string, error) {
	var dataType uint32
	var data []uint16
	var dataSize uint32
	err := syscall.RegQueryValueEx(key.handle, syscall.StringToUTF16Ptr(valueName), nil, &dataType, nil, &dataSize)
	if err != nil {
		return "", err
	}
	data = make([]uint16, dataSize/2)
	err = syscall.RegQueryValueEx(key.handle, syscall.StringToUTF16Ptr(valueName), nil, &dataType, (*byte)(unsafe.Pointer(&data[0])), &dataSize)
	if err != nil {
		return "", err
	}
	return syscall.UTF16ToString(data), nil
}

// 定义一个函数来关闭注册表键
func CloseKey(key *RegistryKey) error {
	return syscall.RegCloseKey(key.handle)
}

func readFile(filePath string) string {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close() // 确保在函数结束时关闭文件

	// 读取文件内容
	contents, err := ioutil.ReadAll(file)
	if err != nil {
		return ""
	}

	return string(contents)
}
