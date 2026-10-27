package main

// Where csq-socks keeps its files: in data\ next to csq-socks.exe, so everything is in the folder that was unpacked
// and deleting it removes csq-socks (after csq-socks down: a connection and tun's kill switch live in Windows, not
// in files; a restart also clears them). Unpacked under Program Files or Windows, which a normal terminal cannot
// write, the files go to %LOCALAPPDATA%\csq-socks instead.
// 1.0.1 kept the link and settings in %APPDATA%\csq-socks, its state in %LOCALAPPDATA%\csq-socks, and ran tun's
// client from %ProgramFiles%\csq-socks: migrate() moves the link and settings over once, stopDaemon() also stops a
// 1.0.1 connection, and an elevated run removes the Program Files copy (a kill switch it left on stays on).

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

var (
	exeDir, dataDir         string
	cfgPath, optPath        string
	run, logPath            string
	portable                bool // the files are next to the exe
	legacyRun, legacyConfig string
)

func setPaths() {
	exe, _ := os.Executable()
	exeDir = filepath.Dir(exe)
	portable = !underSystemDir(exeDir)
	if portable {
		dataDir = filepath.Join(exeDir, "data")
	} else {
		dataDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "csq-socks")
	}
	run = dataDir
	cfgPath = filepath.Join(dataDir, "conn.json")
	optPath = filepath.Join(dataDir, "settings.json")
	logPath = filepath.Join(dataDir, "client.log")
	legacyConfig = filepath.Join(os.Getenv("APPDATA"), "csq-socks")
	if legacyRun = filepath.Join(os.Getenv("LOCALAPPDATA"), "csq-socks"); legacyRun == dataDir {
		legacyRun = ""
	}
}

func underSystemDir(dir string) bool {
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86, windows.FOLDERID_Windows} {
		root, err := windows.KnownFolderPath(id, 0)
		if err != nil || root == "" {
			continue
		}
		if rel, err := filepath.Rel(root, dir); err == nil && rel != ".." && !filepath.IsAbs(rel) &&
			(len(rel) < 3 || rel[:3] != `..\`) {
			return true
		}
	}
	return false
}

// ensureData makes the data folder on first use. Next to the exe, the whole csq-socks folder (when it is just the
// unpacked archive; otherwise data\ alone) then gets a DACL of this user, SYSTEM and Administrators only: unpacked
// straight into C:\ it would inherit "Authenticated Users: Modify", and any local user could read the link's
// password or replace csq-socks.exe, which tun runs elevated.
func ensureData() error {
	if _, err := os.Stat(dataDir); err == nil {
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("csq-socks keeps its files in %s and cannot create it (%v) — unpack it into a folder you can write", dataDir, err)
	}
	if portable && ownFolder(exeDir) {
		protect(exeDir)
	} else {
		protect(dataDir)
	}
	return nil
}

// ownFolder: the folder holds only what the csq-socks archive does (plus data\) — never re-lock a folder csq-socks.exe
// was merely copied into among other programs
func ownFolder(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	ours := map[string]bool{"csq-socks.exe": true, "client-2.5.2.exe": true, "client-2.1.9.exe": true, "wintun.dll": true,
		"README.md": true, "README.en.md": true, "LICENSE": true, "LICENSE-csqtt": true, "LICENSE-wintun.txt": true,
		"NOTICE": true, "VERSION": true, "CLIENTS.sha256": true, "SHA256SUMS": true, "source": true, "data": true}
	for _, e := range ents {
		if !ours[e.Name()] {
			return false
		}
	}
	return true
}

func protect(dir string) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:PAI(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", u.User.Sid))
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	// SetNamedSecurityInfo also hands the inheritable entries down to what is already in the folder
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// migrate: 1.0.1's link and settings, once, into the data folder
func migrate() {
	if legacyRun != "" { // 1.0.1's log; with a state file its connection may still run, and stopDaemon takes both
		if _, err := os.Stat(filepath.Join(legacyRun, "state.json")); err != nil {
			os.RemoveAll(legacyRun)
		}
	}
	if _, err := os.Stat(cfgPath); err == nil || legacyConfig == dataDir {
		return
	}
	for _, f := range []string{"conn.json", "settings.json"} {
		src := filepath.Join(legacyConfig, f)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if ensureData() != nil || moveFile(src, filepath.Join(dataDir, f)) != nil {
			return
		}
	}
	os.Remove(legacyConfig) // only when empty
}

func moveFile(src, dst string) error {
	if os.Rename(src, dst) == nil {
		return nil
	}
	in, err := os.Open(src) // another drive
	if err != nil {
		return err
	}
	b, err := io.ReadAll(in)
	in.Close()
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		return err
	}
	return os.Remove(src)
}

// legacyProgramDir: where 1.0.1's tun ran the client from, and kept its kill-switch marker
func legacyProgramDir() string {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || pf == "" {
		return ""
	}
	return filepath.Join(pf, "csq-socks")
}

// legacyCleanup (elevated): 1.0.1's Program Files copy goes; a kill switch it left on becomes ours, still on
func legacyCleanup() {
	old := legacyProgramDir()
	if old == "" {
		return
	}
	if _, err := os.Stat(old); err != nil {
		return
	}
	if _, err := os.Stat(filepath.Join(old, "killswitch.on")); err == nil && ensureData() == nil {
		os.WriteFile(killSwitchMarker(), []byte("carried over from 1.0.1\n"), 0o600)
	}
	os.RemoveAll(old)
}
