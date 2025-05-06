package main

import (
	"flag"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	TOKEN_ALL_ACCESS             = 0xf01ff
	SECURITY_IMPERSONATION_LEVEL = 2
	TOKEN_TYPE_PRIMARY           = 1
	WTS_CURRENT_SERVER_HANDLE    = 0
	WTSUserName                  = 5
	WTSConnectState              = 4
	WTSActive                    = 0
)

type WTSSessionInfo struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32
}

var (
	modWtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")

	procWTSQueryUserToken           = modWtsapi32.NewProc("WTSQueryUserToken")
	procWTSEnumerateSessionsW       = modWtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSFreeMemory               = modWtsapi32.NewProc("WTSFreeMemory")
	procWTSQuerySessionInformationW = modWtsapi32.NewProc("WTSQuerySessionInformationW")

	modAdvapi32              = syscall.NewLazyDLL("advapi32.dll")
	procDuplicateTokenEx     = modAdvapi32.NewProc("DuplicateTokenEx")
	procCreateProcessAsUserW = modAdvapi32.NewProc("CreateProcessAsUserW")
)

func findActiveUserSession() (uint32, error) {
	var pSessionInfo uintptr
	var count uint32

	r1, _, err := procWTSEnumerateSessionsW.Call(
		0, 0, 1, uintptr(unsafe.Pointer(&pSessionInfo)), uintptr(unsafe.Pointer(&count)),
	)
	if r1 == 0 {
		return 0, err
	}
	defer procWTSFreeMemory.Call(pSessionInfo)

	entries := (*[1 << 16]WTSSessionInfo)(unsafe.Pointer(pSessionInfo))[:count:count]
	for _, entry := range entries {
		var usernamePtr *uint16
		var bytesReturned uint32

		r1, _, _ := procWTSQuerySessionInformationW.Call(
			0,
			uintptr(entry.SessionID),
			uintptr(WTSUserName),
			uintptr(unsafe.Pointer(&usernamePtr)),
			uintptr(unsafe.Pointer(&bytesReturned)),
		)

		if r1 == 0 || bytesReturned == 0 {
			continue
		}

		username := windows.UTF16PtrToString(usernamePtr)
		procWTSFreeMemory.Call(uintptr(unsafe.Pointer(usernamePtr)))

		if entry.State == WTSActive && username != "" {
			return entry.SessionID, nil
		}
	}
	return 0, fmt.Errorf("no active user session found")
}

func queryUserToken(sessionID uint32) (windows.Token, error) {
	var hToken windows.Token
	r1, _, err := procWTSQueryUserToken.Call(uintptr(sessionID), uintptr(unsafe.Pointer(&hToken)))
	if r1 == 0 {
		return 0, err
	}
	return hToken, nil
}

func duplicateToken(hToken windows.Token) (windows.Token, error) {
	var duplicatedToken windows.Token
	r1, _, err := procDuplicateTokenEx.Call(
		uintptr(hToken),
		uintptr(TOKEN_ALL_ACCESS),
		0,
		uintptr(SECURITY_IMPERSONATION_LEVEL),
		uintptr(TOKEN_TYPE_PRIMARY),
		uintptr(unsafe.Pointer(&duplicatedToken)),
	)
	if r1 == 0 {
		return 0, err
	}
	return duplicatedToken, nil
}

func createProcessAsUser(hToken windows.Token, command string) error {
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	cmdline, err := syscall.UTF16PtrFromString(command)
	if err != nil {
		return err
	}

	r1, _, err := procCreateProcessAsUserW.Call(
		uintptr(hToken),
		0,
		uintptr(unsafe.Pointer(cmdline)),
		0, 0, 0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r1 == 0 {
		return err
	}

	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}

func main() {
	ps1Path := flag.String("ps1", "", "Path to the PowerShell script to execute")
	flag.Parse()

	sessionID, err := findActiveUserSession()
	if err != nil {
		log.Fatalf("Failed to find user session: %v", err)
	}

	userToken, err := queryUserToken(sessionID)
	if err != nil {
		log.Fatalf("queryUserToken failed: %v", err)
	}
	defer userToken.Close()

	dupToken, err := duplicateToken(userToken)
	if err != nil {
		log.Fatalf("duplicateToken failed: %v", err)
	}
	defer dupToken.Close()

	scriptPath := *ps1Path
	command := fmt.Sprintf(`powershell.exe -ExecutionPolicy Bypass -File "%s"`, scriptPath)

	err = createProcessAsUser(dupToken, command)
	if err != nil {
		log.Fatalf("createProcessAsUser failed: %v", err)
	}

	fmt.Println("Process launched successfully in user session.")
}
