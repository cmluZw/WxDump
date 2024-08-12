package comm

import (
	"bytes"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	createToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	module32First            = kernel32.NewProc("Module32FirstW")
	module32Next             = kernel32.NewProc("Module32NextW")
	closeHandle              = kernel32.NewProc("CloseHandle")
	TH32CS_SNAPMODULE        = 0x00000008
	TH32CS_SNAPMODULE32      = 0x00000010
)

type MODULEENTRY32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlobalUsage  uint32
	ProccntUsage uint32
	modBaseAddr  uintptr
	ModBaseSize  uint32
	hModule      syscall.Handle
	ModuleName   [256]uint16
	ExePath      [260]uint16
}

func getModuleInfo(pid uint32, moduleName string) (uintptr, uintptr, error) {
	snapshot, _, _ := createToolhelp32Snapshot.Call(0x00000008, uintptr(pid))
	if snapshot == uintptr(syscall.InvalidHandle) {
		return 0, 0, fmt.Errorf("failed to create snapshot")
	}
	defer closeHandle.Call(snapshot)

	var mod MODULEENTRY32
	mod.Size = uint32(unsafe.Sizeof(mod))

	ret, _, _ := module32First.Call(snapshot, uintptr(unsafe.Pointer(&mod)))
	for ret != 0 {
		name := syscall.UTF16ToString(mod.ModuleName[:])
		if name == moduleName {
			return mod.modBaseAddr, uintptr(mod.ModBaseSize), nil
		}
		ret, _, _ = module32Next.Call(snapshot, uintptr(unsafe.Pointer(&mod)))
	}

	return 0, 0, fmt.Errorf("module %s not found", moduleName)
}

func readProcessMemoryBytes(hProcess syscall.Handle, address uintptr, size int) ([]byte, error) {
	data := make([]byte, size)
	read := 0
	ret, _, _ := readProcessMemory.Call(uintptr(hProcess), address, uintptr(unsafe.Pointer(&data[0])), uintptr(size), uintptr(unsafe.Pointer(&read)))
	if ret == 0 {
		return nil, fmt.Errorf("failed to read process memory")
	}
	return data, nil
}

func searchPattern(data []byte, pattern []byte) []int {
	var positions []int
	for i := 0; i < len(data)-len(pattern); i++ {
		if bytes.Equal(data[i:i+len(pattern)], pattern) {
			positions = append(positions, i)
		}
	}
	return positions
}

func PatternScanModule(pid uint32, moduleName string, pattern []byte, returnMultiple bool) ([]uintptr, error) {
	//这里使用了0x1F0FFF替换了原本的syscall.PROCESS_ALL_ACCESS
	hProcess, err := syscall.OpenProcess(0x1F0FFF, false, pid)
	if err != nil {
		return nil, fmt.Errorf("failed to open process: %v", err)
	}
	defer syscall.CloseHandle(hProcess)

	moduleBaseAddress, moduleSize, err := getModuleInfo(pid, moduleName)
	if err != nil {
		return nil, err
	}

	moduleData, err := readProcessMemoryBytes(hProcess, moduleBaseAddress, int(moduleSize))
	if err != nil {
		return nil, err
	}

	positions := searchPattern(moduleData, pattern)
	if len(positions) == 0 {
		return nil, nil
	}

	var results []uintptr
	for _, pos := range positions {
		results = append(results, moduleBaseAddress+uintptr(pos))
		if !returnMultiple {
			break
		}
	}

	return results, nil
}
