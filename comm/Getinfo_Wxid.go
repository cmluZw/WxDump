package comm

//V1.0.0
//By cmluZw 2024-08-12

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

// 定义需要的Windows API函数
var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	virtualQueryEx    = kernel32.NewProc("VirtualQueryEx")
	readProcessMemory = kernel32.NewProc("ReadProcessMemory")
)

// MEMORY_BASIC_INFORMATION结构体定义
type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func patternScanAll(handle syscall.Handle, pattern []byte, returnMultiple bool, findNum int) ([]uintptr, error) {
	var found []uintptr
	nextRegion := uintptr(0)
	userSpaceLimit := uintptr(0x7FFFFFFF0000)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		userSpaceLimit = 0x7fff0000
	}

	for nextRegion < userSpaceLimit {
		mbi := MEMORY_BASIC_INFORMATION{}
		mbiSize := unsafe.Sizeof(mbi)
		ret, _, _ := virtualQueryEx.Call(uintptr(handle), nextRegion, uintptr(unsafe.Pointer(&mbi)), mbiSize)
		if ret == 0 {
			break
		}

		// 如果是可读内存区域
		if mbi.State == windows.MEM_COMMIT && (mbi.Protect == syscall.PAGE_READWRITE || mbi.Protect == syscall.PAGE_EXECUTE_READWRITE) {
			pageFound := scanPatternPage(handle, mbi.BaseAddress, mbi.RegionSize, pattern, returnMultiple)
			if !returnMultiple && len(pageFound) > 0 {
				return pageFound, nil
			}
			if len(pageFound) > 0 {
				found = append(found, pageFound...)
			}
			if len(found) > findNum {
				break
			}
		}

		nextRegion = mbi.BaseAddress + mbi.RegionSize
	}

	return found, nil
}

func scanPatternPage(handle syscall.Handle, baseAddr uintptr, regionSize uintptr, pattern []byte, returnMultiple bool) []uintptr {
	var found []uintptr
	buffer := make([]byte, regionSize)
	read := 0
	ret, _, _ := readProcessMemory.Call(uintptr(handle), baseAddr, uintptr(unsafe.Pointer(&buffer[0])), uintptr(regionSize), uintptr(unsafe.Pointer(&read)))
	if ret == 0 {
		return found
	}

	for i := 0; i < len(buffer)-len(pattern); i++ {
		if bytes.Equal(buffer[i:i+len(pattern)], pattern) {
			found = append(found, baseAddr+uintptr(i))
			if !returnMultiple {
				break
			}
		}
	}

	return found
}

func getInfoWxid(hProcess syscall.Handle) (string, error) {
	findNum := 100
	addrs, err := patternScanAll(hProcess, []byte(`\Msg\FTSContact`), true, findNum)
	if err != nil {
		return "None", err
	}
	wxids := make([]string, 0)
	for _, addr := range addrs {
		array := make([]byte, 80)
		read := 0
		ret, _, _ := readProcessMemory.Call(uintptr(hProcess), addr-30, uintptr(unsafe.Pointer(&array[0])), 80, uintptr(unsafe.Pointer(&read)))
		if ret == 0 {
			return "None", nil
		}
		array = bytes.Split(array, []byte(`\Msg`))[0] // 处理前缀
		parts := bytes.Split(array, []byte(`\`))      // 分割字节切片
		lastPart := parts[len(parts)-1]               // 获取最后一部分
		wxid := string(lastPart)                      // 将最后一部分转换为字符串
		wxids = append(wxids, wxid)
	}
	if len(wxids) == 0 {
		return "None", nil
	}
	return mostCommonString(wxids), nil
}

func mostCommonString(arr []string) string {
	freqMap := make(map[string]int)
	maxFreq := 0
	mostCommon := ""
	for _, str := range arr {
		freqMap[str]++
		if freqMap[str] > maxFreq {
			maxFreq = freqMap[str]
			mostCommon = str
		}
	}
	return mostCommon
}

func Get_result() string {
	process, _ := GetWeChatProcess()
	wechatProcessHandle, _ := windows.OpenProcess(0x1F0FFF, false, process.ProcessID) //原来0x1F0FFF是PROCESS_ALL_ACCESS
	handle := syscall.Handle(wechatProcessHandle)
	// 示例调用
	//handle := syscall.Handle(0x1234) // 假设这是一个有效的进程句柄
	wxid, err := getInfoWxid(handle)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return wxid
}
