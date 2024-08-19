package comm

//V1.0.0
//By cmluZw 2024-08-12

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

// 获取微信进程对象，包含进程ID、进程句柄和Module列表
func GetWeChatProcess() (windows.ProcessEntry32, error) {
	var process windows.ProcessEntry32
	process.Size = uint32(unsafe.Sizeof(process))
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return process, err
	}
	defer windows.CloseHandle(snapshot)
	for {
		err = windows.Process32Next(snapshot, &process)
		if err != nil {
			return process, err
		}
		if windows.UTF16ToString(process.ExeFile[:]) == "WeChat.exe" {
			return process, nil
		}
	}
}

// 获取微信进程的WeChatWin.dll模块对象，包含模块基址、模块大小和模块路径()
func GetWeChatWinModule(process windows.ProcessEntry32) (windows.ModuleEntry32, error) {
	var module windows.ModuleEntry32
	module.Size = uint32(unsafe.Sizeof(module))
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, process.ProcessID)
	if err != nil {
		return module, err
	}
	defer windows.CloseHandle(snapshot)
	for {
		err = windows.Module32Next(snapshot, &module)
		if err != nil {
			return module, err
		}
		if windows.UTF16ToString(module.Module[:]) == "WeChatWin.dll" {
			return module, nil
		}
	}
}

// 通过模块获取版本号 c#代码为：string FileVersion = processModule.FileVersionInfo.FileVersion;转成go代码如下
func GetVersion(module windows.ModuleEntry32) (string, error) {
	image, imgErr := windows.LoadLibraryEx(windows.UTF16ToString(module.ExePath[:]), 0, windows.LOAD_LIBRARY_AS_DATAFILE)
	if imgErr != nil {
		return "", fmt.Errorf("LoadLibraryEx error: %v", imgErr)
	}
	resInfo, infoErr := windows.FindResource(image, windows.ResourceID(1), windows.RT_VERSION)
	if infoErr != nil {
		return "", fmt.Errorf("FindResource error: %v", infoErr)
	}
	resData, dataErr := windows.LoadResourceData(image, resInfo)
	if dataErr != nil {
		return "", fmt.Errorf("LoadResourceData error: %v", dataErr)
	}
	var info *windows.VS_FIXEDFILEINFO
	size := uint32(unsafe.Sizeof(*info))
	err := windows.VerQueryValue(unsafe.Pointer(&resData[0]), `\`, unsafe.Pointer(&info), &size)
	if err != nil {
		return "", fmt.Errorf("VerQueryValue error: %v", err)
	}
	// 从低位到高位，分别为主版本号、次版本号、修订号、编译号
	version := fmt.Sprintf("%d.%d.%d.%d", info.FileVersionMS>>16, info.FileVersionMS&0xffff, info.FileVersionLS>>16, info.FileVersionLS&0xffff)
	return version, nil
}

// 获取微信数据：入参为微信进程句柄，偏移地址，返回值为昵称和错误信息
func GetWeChatData(process windows.Handle, offset uintptr, nSize int) (string, error) {
	var buffer = make([]byte, nSize)
	err := windows.ReadProcessMemory(process, offset, &buffer[0], uintptr(nSize), nil)
	if err != nil {
		return "", err
	}
	// 声明一个字节数组，暂时为空
	var textBytes []byte = nil
	for _, v := range buffer {
		if v == 0 {
			break
		}
		textBytes = append(textBytes, v)
	}
	// 返回utf8编码的字符串
	return string(textBytes), nil
}

// 获取微信key：入参为微信进程句柄，偏移地址，返回值为key和错误信息
func GetWeChatKey(process windows.Handle, offset uintptr) (string, error) {
	var buffer = make([]byte, 4)
	err := windows.ReadProcessMemory(process, offset, &buffer[0], 4, nil)
	if err != nil {
		return "", err
	}
	var num = 32
	var buffer2 = make([]byte, num)
	// c# 代码(IntPtr)(((int)array[3] << 24) + ((int)array[2] << 16) + ((int)array[1] << 8) + (int)array[0]);转成go代码如下
	offset2 := uintptr((int(buffer[3]) << 24) + (int(buffer[2]) << 16) + (int(buffer[1]) << 8) + int(buffer[0]))
	err = windows.ReadProcessMemory(process, offset2, &buffer2[0], uintptr(num), nil)
	if err != nil {
		return "", err
	}
	// 将byte数组转成hex字符串，并转成大写
	key := hex.EncodeToString(buffer2)
	key = strings.ToUpper(key)
	return key, nil
}

func GetWeChatKey64(process windows.Handle, offset uintptr) (string, error) {
	var buffer = make([]byte, 8)
	err := windows.ReadProcessMemory(process, offset, &buffer[0], 8, nil)
	if err != nil {
		return "", err
	}
	var num = 32
	var buffer2 = make([]byte, num)
	offset2 := uintptr(
		(uint64(buffer[7]) << 56) + (uint64(buffer[6]) << 48) + (uint64(buffer[5]) << 40) + (uint64(buffer[4]) << 32) +
			(uint64(buffer[3]) << 24) + (uint64(buffer[2]) << 16) + (uint64(buffer[1]) << 8) + (uint64(buffer[0]) << 0))
	err = windows.ReadProcessMemory(process, offset2, &buffer2[0], uintptr(num), nil)
	if err != nil {
		return "", err
	}
	// 将byte数组转成hex字符串，并转成大写
	key := hex.EncodeToString(buffer2)
	key = strings.ToUpper(key)
	return key, nil
}

func Get_info() (bool, string, string, string) {
	is_normal := false
	versionList := Get_version_list()
	process, _ := GetWeChatProcess()
	module, _ := GetWeChatWinModule(process)
	base_addr := module.ModBaseAddr
	version, _ := GetVersion(module)
	fmt.Println("当前微信版本: ", version)
	wechatProcessHandle, _ := windows.OpenProcess(0x1F0FFF, false, process.ProcessID) //原来0x1F0FFF是PROCESS_ALL_ACCESS
	//version = "3.9.8.25"
	if len(versionList[version]) == 0 {
		fmt.Println("微信版本范围超过已有配置")
		return false, "", "", ""
	}

	nickName, err := GetWeChatData(wechatProcessHandle, base_addr+uintptr(versionList[version][0]), 64)
	if err != nil {
		fmt.Println("Error:", err)
		return false, "", "", ""
	}
	account, err := GetWeChatData(wechatProcessHandle, base_addr+uintptr(versionList[version][1]), 32)
	if err != nil {
		fmt.Println("Error:", err)
		return false, "", "", ""
	}
	fmt.Println(nickName, account)
	key, err := GetWeChatKey64(wechatProcessHandle, base_addr+uintptr(versionList[version][4]))
	if err != nil {
		fmt.Println("Error:", err)
		return false, "", "", ""
	}
	if len(key) == 0 {
		fmt.Println("找不到key")
		return false, nickName, account, key
	}
	is_normal = true
	return is_normal, nickName, account, key
}
