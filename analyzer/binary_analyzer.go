package analyzer

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	MaxFileSize        = 250 * 1024 * 1024
	MaxSectionDataRead = 50 * 1024 * 1024

	MinPESize = 64

	MaxZipEntries         = 2048
	MaxZipMemberBytes     = 2 * 1024 * 1024
	MaxZipTotalBytesRead  = 30 * 1024 * 1024
	MaxZipRecursionDepth  = 1
	MaxStringsReadPerFile = 1024 * 1024
)

type BinaryFeatures struct {
	Entropy    float64
	FileSize   int64
	SHA256Hash string

	OverlaySize  int64
	OverlayRatio float64

	SectionCount      int
	ImportCount       int
	ExportCount       int
	ResourceCount     int
	TLSCallbackCount  int
	HasDebugInfo      int
	HasOverlay        int
	HasRelocations    int
	HasResources      int
	HasTLS            int
	IsDLL             int
	Is64Bit           int
	HasNXCompat       int
	HasDEP            int
	HasASLR           int
	HasSEH            int
	HasCFG            int
	IsSigned          int
	SuspiciousAPIs    int
	SuspiciousStrings int
	PackedIndicator   int

	WritableExecutableSections int
	SuspiciousSections         int
	AnomalousTimestamp         int
	LowImportCount             int

	CodeSectionEntropy   float64
	DataSectionEntropy   float64
	MaxSectionEntropy    float64
	MinSectionEntropy    float64
	AvgSectionEntropy    float64
	SectionEntropyStdDev float64

	CodeToDataRatio     float64
	ImportToExportRatio float64
	ResourceSizeRatio   float64

	UniqueDLLCount     int
	ImportDensity      float64
	SuspiciousDLLs     int
	ASCIIStringCount   int
	UnicodeStringCount int
	URLCount           int
	IPAddressCount     int
	RegistryKeyCount   int
	FilePathCount      int

	CompileTimestamp int64
	TimestampAge     float64

	EPSectionEntropy   float64
	EPInLastSection    int
	SectionNameEntropy float64
}

var suspiciousAPIList = []string{
	"VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
	"WriteProcessMemory", "ReadProcessMemory", "NtAllocateVirtualMemory",

	"CreateRemoteThread", "CreateRemoteThreadEx", "RtlCreateUserThread",
	"NtCreateThread", "NtCreateThreadEx", "QueueUserAPC", "NtQueueApcThread",
	"CreateProcess", "CreateProcessInternal", "ShellExecute", "WinExec",
	"ResumeThread", "SuspendThread", "NtResumeThread", "NtSuspendThread",
	"TerminateProcess", "NtTerminateProcess",

	"SetWindowsHookEx", "SetThreadContext", "NtSetContextThread",
	"NtUnmapViewOfSection", "NtMapViewOfSection",

	"LoadLibrary", "LoadLibraryEx", "GetProcAddress", "LdrLoadDll",
	"LdrGetProcedureAddress",

	"RegSetValue", "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx",
	"RegDeleteKey", "RegDeleteValue", "NtSetValueKey", "NtDeleteKey",

	"CreateFile", "WriteFile", "DeleteFile", "MoveFile", "CopyFile",
	"FindFirstFile", "FindNextFile",

	"URLDownloadToFile", "InternetOpen", "InternetConnect", "InternetOpenUrl",
	"HttpSendRequest", "HttpOpenRequest", "send", "recv", "WSAStartup",
	"connect", "socket", "bind", "listen", "accept",

	"CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptCreateHash",
	"CryptHashData", "CryptDeriveKey",

	"CreateService", "ControlService", "ChangeServiceConfig",

	"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
	"OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
	"ZwSetInformationThread",

	"AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken",
}

var suspiciousDLLList = []string{
	"ntdll.dll", "advapi32.dll", "ws2_32.dll",
	"wininet.dll", "urlmon.dll", "crypt32.dll",
	"winsock", "vaultcli.dll",
}

var suspiciousStringPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(keylogger|backdoor|rootkit|inject|payload|shellcode)`),
	regexp.MustCompile(`(?i)(sandbox|virtual|vmware|vbox|qemu|wine)`),
	regexp.MustCompile(`(?i)(malware|virus|trojan|ransomware|cryptolocker)`),
	regexp.MustCompile(`(?i)(cmd\.exe|powershell|wscript|cscript)`),
}

var (
	asciiPattern = regexp.MustCompile(`[ -~]{4,}`)
	urlPattern   = regexp.MustCompile(`https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}`)
	ipPattern    = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	regPattern   = regexp.MustCompile(`(?i)HKEY_[A-Z_]+\\[\\a-zA-Z0-9_\-]+`)
	pathPattern  = regexp.MustCompile(`[A-Za-z]:\\[\\a-zA-Z0-9_\-\.]+`)
)

type fileKind int

const (
	kindUnknown fileKind = iota
	kindPE
	kindELF
	kindMachO
	kindZip
)

func ExtractFeatures(filepath string) (*BinaryFeatures, error) {
	if filepath == "" {
		return nil, errors.New("empty filepath provided")
	}

	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	fileSize := stat.Size()
	if fileSize < 0 {
		return nil, fmt.Errorf("invalid file size: %d", fileSize)
	}
	if fileSize > MaxFileSize {
		return nil, fmt.Errorf("file too large: %d bytes (max: %d)", fileSize, MaxFileSize)
	}

	features := &BinaryFeatures{
		FileSize:          fileSize,
		MinSectionEntropy: 8.0,
	}

	if hash, err := calculateSHA256(file); err == nil {
		features.SHA256Hash = hash
	}
	features.Entropy = safeCalculateEntropy(file)
	_ = extractStringsFromReadSeeker(file, features, MaxStringsReadPerFile)

	k := detectKind(file, fileSize)

	switch k {
	case kindPE:
		if fileSize < MinPESize {
			return features, nil
		}

		peFile, err := pe.NewFile(file)
		if err != nil {
			return features, nil
		}
		defer peFile.Close()

		if err := extractPEFeatures(peFile, features, file); err != nil {
			return features, nil
		}

	case kindELF:
		_ = analyzeELF(file, features)

	case kindMachO:
		_ = analyzeMachO(file, features)

	case kindZip:
		_ = analyzeZipPath(filepath, features, 0)

	default:
	}

	return features, nil
}

func detectKind(r io.ReaderAt, size int64) fileKind {
	if isPE(r, size) {
		return kindPE
	}
	if hasMagic(r, 0, []byte{0x7f, 'E', 'L', 'F'}) {
		return kindELF
	}
	if isMachO(r) {
		return kindMachO
	}
	if isZip(r) {
		return kindZip
	}
	return kindUnknown
}

func hasMagic(r io.ReaderAt, off int64, m []byte) bool {
	buf := make([]byte, len(m))
	if _, err := r.ReadAt(buf, off); err != nil {
		return false
	}
	return bytes.Equal(buf, m)
}

func isPE(r io.ReaderAt, size int64) bool {
	if size < MinPESize {
		return false
	}
	if !hasMagic(r, 0, []byte{'M', 'Z'}) {
		return false
	}
	var off [4]byte
	if _, err := r.ReadAt(off[:], 0x3c); err != nil {
		return false
	}
	e := int64(binary.LittleEndian.Uint32(off[:]))
	if e < 0 || e+4 > size {
		return false
	}
	return hasMagic(r, e, []byte{'P', 'E', 0, 0})
}

func isZip(r io.ReaderAt) bool {
	return hasMagic(r, 0, []byte{'P', 'K', 0x03, 0x04}) ||
		hasMagic(r, 0, []byte{'P', 'K', 0x05, 0x06}) ||
		hasMagic(r, 0, []byte{'P', 'K', 0x07, 0x08})
}

func isMachO(r io.ReaderAt) bool {
	var b [4]byte
	if _, err := r.ReadAt(b[:], 0); err != nil {
		return false
	}
	be := binary.BigEndian.Uint32(b[:])
	le := binary.LittleEndian.Uint32(b[:])

	switch be {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE, 0xCAFEBABF:
		return true
	}

	switch le {
	case 0xCEFAEDFE, 0xCFFAEDFE, 0xBEBAFECA, 0xBFBAFECA:
		return true
	}
	return false
}

func calculateSHA256(r io.ReadSeeker) (string, error) {
	if _, err := r.Seek(0, 0); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, r); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func safeCalculateEntropy(r io.ReadSeeker) float64 {
	defer func() { _ = recover() }()

	if _, err := r.Seek(0, 0); err != nil {
		return 0
	}

	counts := make([]int, 256)
	total := 0
	buf := make([]byte, 8192)

	for total < MaxSectionDataRead {
		n, err := r.Read(buf)
		if n > 0 {
			for i := 0; i < n; i++ {
				counts[buf[i]]++
			}
			total += n
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0
		}
	}

	if total == 0 {
		return 0
	}

	ent := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		ent -= p * math.Log2(p)
	}
	return ent
}

func extractStringsFromReadSeeker(rs io.ReadSeeker, features *BinaryFeatures, limit int) error {
	if features == nil {
		return errors.New("nil features")
	}
	if _, err := rs.Seek(0, 0); err != nil {
		return err
	}

	buf := make([]byte, limit)
	n, err := rs.Read(buf)
	if err != nil && err != io.EOF {
		return err
	}
	return extractStringsFromBytes(buf[:n], features)
}

func extractStringsFromBytes(buf []byte, features *BinaryFeatures) error {
	if features == nil {
		return errors.New("nil features")
	}
	if len(buf) == 0 {
		return nil
	}

	asciiMatches := asciiPattern.FindAll(buf, -1)
	features.ASCIIStringCount += len(asciiMatches)

	features.URLCount += len(urlPattern.FindAll(buf, -1))
	features.IPAddressCount += len(ipPattern.FindAll(buf, -1))
	features.RegistryKeyCount += len(regPattern.FindAll(buf, -1))
	features.FilePathCount += len(pathPattern.FindAll(buf, -1))

	for _, pattern := range suspiciousStringPatterns {
		features.SuspiciousStrings += len(pattern.FindAll(buf, -1))
	}

	return nil
}

func extractPEFeatures(peFile *pe.File, features *BinaryFeatures, file *os.File) error {
	if peFile == nil || features == nil {
		return errors.New("nil pointer provided")
	}

	if peFile.FileHeader.TimeDateStamp != 0 {
		ts := int64(peFile.FileHeader.TimeDateStamp)
		features.CompileTimestamp = ts
		features.TimestampAge = time.Since(time.Unix(ts, 0)).Hours() / 24.0
		if ts < 315532800 {
			features.AnomalousTimestamp = 1
		}
	}

	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_ARM64:
		features.Is64Bit = 1
	}

	if peFile.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		features.IsDLL = 1
	}

	if peFile.Characteristics&pe.IMAGE_FILE_RELOCS_STRIPPED == 0 {
		features.HasRelocations = 1
	}

	if err := analyzeSections(peFile, features); err != nil {
		return err
	}

	if err := analyzeImports(peFile, features); err == nil {
		if features.ImportCount < 5 && features.FileSize > 10000 {
			features.LowImportCount = 1
		}
	}

	analyzeExports(peFile, features)

	if err := analyzeOptionalHeader(peFile, features); err != nil {
		return err
	}

	analyzeResources(peFile, features)

	if file != nil {
		_ = extractStringsFromReadSeeker(file, features, MaxStringsReadPerFile)
	}

	detectOverlay(peFile, features)

	detectPacking(features)
	return nil
}

func analyzeSections(peFile *pe.File, features *BinaryFeatures) error {
	if peFile.Sections == nil {
		return nil
	}

	features.SectionCount = len(peFile.Sections)

	epRVA := peEntryPointRVA(peFile)
	epSectionIndex := -1
	if epRVA != 0 {
		for i, s := range peFile.Sections {
			if rvaInSection(epRVA, s) {
				epSectionIndex = i
				break
			}
		}
	}

	var entropies []float64
	var codeSize, dataSize int64
	sectionNames := make([]string, 0, len(peFile.Sections))

	const (
		IMAGE_SCN_MEM_EXECUTE = 0x20000000
		IMAGE_SCN_MEM_WRITE   = 0x80000000
		IMAGE_SCN_CNT_CODE    = 0x00000020
	)

	for i, section := range peFile.Sections {
		if section == nil {
			continue
		}

		sectionName := strings.TrimRight(string(section.Name[:]), "\x00")
		sectionNames = append(sectionNames, sectionName)

		if (section.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0) &&
			(section.Characteristics&IMAGE_SCN_MEM_WRITE != 0) {
			features.WritableExecutableSections++
		}

		if isSuspiciousSectionName(sectionName) {
			features.SuspiciousSections++
		}

		data, err := section.Data()
		if err == nil && len(data) > 0 && len(data) <= MaxSectionDataRead {
			ent := calculateBytesEntropy(data)
			entropies = append(entropies, ent)

			if ent > features.MaxSectionEntropy {
				features.MaxSectionEntropy = ent
			}
			if ent < features.MinSectionEntropy {
				features.MinSectionEntropy = ent
			}
			if i == epSectionIndex {
				features.EPSectionEntropy = ent
			}

			if section.Characteristics&IMAGE_SCN_CNT_CODE != 0 || strings.HasPrefix(sectionName, ".text") {
				features.CodeSectionEntropy = ent
				codeSize += int64(len(data))
			}
			if strings.HasPrefix(sectionName, ".data") || strings.HasPrefix(sectionName, ".rdata") {
				features.DataSectionEntropy = ent
				dataSize += int64(len(data))
			}
		}
	}

	if epSectionIndex >= 0 && epSectionIndex == len(peFile.Sections)-1 {
		features.EPInLastSection = 1
	}

	if len(entropies) > 0 {
		sum := 0.0
		for _, e := range entropies {
			sum += e
		}
		features.AvgSectionEntropy = sum / float64(len(entropies))

		variance := 0.0
		for _, e := range entropies {
			d := e - features.AvgSectionEntropy
			variance += d * d
		}
		features.SectionEntropyStdDev = math.Sqrt(variance / float64(len(entropies)))
	}

	if dataSize > 0 {
		features.CodeToDataRatio = float64(codeSize) / float64(dataSize)
	}

	features.SectionNameEntropy = calculateStringEntropy(strings.Join(sectionNames, ""))
	return nil
}

func isSuspiciousSectionName(name string) bool {
	suspicious := []string{".upx", ".aspack", ".petite", ".mpress", ".nsp", ".packed", ".enigma", ".themida", ".vmp", ".!packed", ".mzalv", ".iopacker", ".iohp"}
	lower := strings.ToLower(name)
	for _, sus := range suspicious {
		if strings.Contains(lower, sus) {
			return true
		}
	}
	if len(name) > 0 && (name[0] < 'A' || name[0] > 'z') {
		return true
	}
	return false
}

func analyzeImports(peFile *pe.File, features *BinaryFeatures) error {
	imports, err := peFile.ImportedSymbols()
	if err != nil {
		return err
	}

	features.ImportCount = len(imports)

	dllSet := make(map[string]bool)
	for _, imp := range imports {
		parts := strings.Split(imp, ":")
		if len(parts) >= 1 {
			dllName := strings.ToLower(parts[0])
			dllSet[dllName] = true
			for _, susDLL := range suspiciousDLLList {
				if strings.Contains(dllName, strings.ToLower(susDLL)) {
					features.SuspiciousDLLs++
					break
				}
			}
		}
		for _, AmogusAPI := range suspiciousAPIList {
			if strings.Contains(imp, AmogusAPI) {
				features.SuspiciousAPIs++
				break
			}
		}
	}

	features.UniqueDLLCount = len(dllSet)

	if features.FileSize > 0 {
		features.ImportDensity = float64(features.ImportCount) / float64(features.FileSize) * 1000.0
	}
	return nil
}

func analyzeExports(peFile *pe.File, features *BinaryFeatures) {
	if peFile.OptionalHeader == nil {
		return
	}

	var dataDir []pe.DataDirectory
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDir = oh.DataDirectory[:]
	case *pe.OptionalHeader64:
		dataDir = oh.DataDirectory[:]
	default:
		return
	}

	if len(dataDir) <= pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
		return
	}

	exportDir := dataDir[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress != 0 && exportDir.Size > 0 {
		features.ExportCount = int(exportDir.Size / 4)

		if features.ExportCount > 0 {
			features.ImportToExportRatio = float64(features.ImportCount) / float64(features.ExportCount)
		} else if features.ImportCount > 0 {
			features.ImportToExportRatio = 999.0
		}
	}
}

func analyzeOptionalHeader(peFile *pe.File, features *BinaryFeatures) error {
	if peFile.OptionalHeader == nil {
		return nil
	}

	var dataDir []pe.DataDirectory
	var dllCharacteristics uint16

	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDir = oh.DataDirectory[:]
		dllCharacteristics = oh.DllCharacteristics
	case *pe.OptionalHeader64:
		dataDir = oh.DataDirectory[:]
		dllCharacteristics = oh.DllCharacteristics
	default:
		return nil
	}

	const (
		IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
		IMAGE_DLLCHARACTERISTICS_NX_COMPAT    = 0x0100
		IMAGE_DLLCHARACTERISTICS_NO_SEH       = 0x0400
		IMAGE_DLLCHARACTERISTICS_GUARD_CF     = 0x4000
	)

	if dllCharacteristics&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 {
		features.HasASLR = 1
	}
	if dllCharacteristics&IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
		features.HasNXCompat = 1
		features.HasDEP = 1
	}
	if dllCharacteristics&IMAGE_DLLCHARACTERISTICS_NO_SEH == 0 {
		features.HasSEH = 1
	}
	if dllCharacteristics&IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
		features.HasCFG = 1
	}

	if len(dataDir) > pe.IMAGE_DIRECTORY_ENTRY_DEBUG {
		debugDir := dataDir[pe.IMAGE_DIRECTORY_ENTRY_DEBUG]
		if debugDir.VirtualAddress != 0 {
			features.HasDebugInfo = 1
		}
	}

	if len(dataDir) > pe.IMAGE_DIRECTORY_ENTRY_RESOURCE {
		resourceDir := dataDir[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
		if resourceDir.VirtualAddress != 0 {
			features.HasResources = 1
			if features.FileSize > 0 {
				features.ResourceSizeRatio = float64(resourceDir.Size) / float64(features.FileSize)
			}
		}
	}

	if len(dataDir) > pe.IMAGE_DIRECTORY_ENTRY_TLS {
		tlsDir := dataDir[pe.IMAGE_DIRECTORY_ENTRY_TLS]
		if tlsDir.VirtualAddress != 0 {
			features.HasTLS = 1
		}
	}

	if len(dataDir) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
		certDir := dataDir[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		if certDir.VirtualAddress != 0 && certDir.Size > 0 {
			features.IsSigned = 1
		}
	}

	return nil
}

func analyzeResources(peFile *pe.File, features *BinaryFeatures) {
	defer func() { _ = recover() }()

	if peFile == nil || features == nil || peFile.OptionalHeader == nil {
		return
	}

	var dataDir []pe.DataDirectory
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDir = oh.DataDirectory[:]
	case *pe.OptionalHeader64:
		dataDir = oh.DataDirectory[:]
	default:
		return
	}
	if len(dataDir) <= pe.IMAGE_DIRECTORY_ENTRY_RESOURCE {
		return
	}

	rd := dataDir[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
	if rd.VirtualAddress == 0 || rd.Size == 0 {
		features.ResourceCount = 0
		return
	}

	var sec *pe.Section
	for _, s := range peFile.Sections {
		if rvaInSection(rd.VirtualAddress, s) {
			sec = s
			break
		}
	}
	if sec == nil {
		return
	}

	raw, err := sec.Data()
	if err != nil || len(raw) < 16 {
		return
	}

	if rd.VirtualAddress < sec.VirtualAddress {
		return
	}
	startU := rd.VirtualAddress - sec.VirtualAddress
	if startU >= uint32(len(raw)) {
		return
	}
	start := int(startU)
	data := raw[start:]
	if rd.Size > 0 {
		if int(rd.Size) < len(data) {
			data = data[:int(rd.Size)]
		}
	}

	features.ResourceCount = countPEResourceLeaves(data)
	if features.ResourceCount > 0 {
		features.HasResources = 1
	}
}

func countPEResourceLeaves(data []byte) int {
	if len(data) < 16 {
		return 0
	}

	const (
		entryIsDirectory = 0x80000000
		offsetMask       = 0x7fffffff

		maxDepth       = 16
		maxDirsVisited = 1_000_000
	)

	visited := make(map[uint32]struct{}, 64)
	dirsVisited := 0

	var walk func(dirOff uint32, depth int) int
	walk = func(dirOff uint32, depth int) int {
		if depth > maxDepth || dirsVisited > maxDirsVisited {
			return 0
		}
		if dirOff > uint32(len(data)) || uint32(len(data))-dirOff < 16 {
			return 0
		}
		if _, ok := visited[dirOff]; ok {
			return 0
		}
		visited[dirOff] = struct{}{}
		dirsVisited++

		nNamed := binary.LittleEndian.Uint16(data[dirOff+12 : dirOff+14])
		nIDs := binary.LittleEndian.Uint16(data[dirOff+14 : dirOff+16])
		n := int(nNamed) + int(nIDs)
		if n <= 0 {
			return 0
		}

		entriesOff := dirOff + 16
		if entriesOff > uint32(len(data)) {
			return 0
		}
		remain := uint32(len(data)) - entriesOff
		maxEntries := int(remain / 8)
		if n > maxEntries {
			n = maxEntries
		}

		leafCount := 0
		for i := 0; i < n; i++ {
			eoff := entriesOff + uint32(i*8)
			if uint32(len(data))-eoff < 8 {
				break
			}

			offsetTo := binary.LittleEndian.Uint32(data[eoff+4 : eoff+8])
			target := offsetTo & offsetMask

			if (offsetTo & entryIsDirectory) != 0 {
				leafCount += walk(target, depth+1)
				continue
			}

			if target > uint32(len(data)) || uint32(len(data))-target < 16 {
				continue
			}
			leafCount++
		}

		return leafCount
	}

	return walk(0, 0)
}

func detectOverlay(peFile *pe.File, features *BinaryFeatures) {
	if len(peFile.Sections) == 0 || features.FileSize <= 0 {
		return
	}

	var maxOffset uint32
	for _, section := range peFile.Sections {
		if section == nil {
			continue
		}
		end := section.Offset + section.Size
		if end > maxOffset {
			maxOffset = end
		}
	}

	overlaySize := int64(features.FileSize) - int64(maxOffset)
	if overlaySize > 0 {
		features.HasOverlay = 1
		features.OverlaySize = overlaySize
		features.OverlayRatio = float64(overlaySize) / float64(features.FileSize)
	}
}

func detectPacking(features *BinaryFeatures) {
	score := 0

	if features.CodeSectionEntropy > 7.0 {
		score += 3
	} else if features.CodeSectionEntropy > 6.5 {
		score += 2
	}

	if features.ImportCount < 10 {
		score += 2
	}

	if features.SectionEntropyStdDev > 1.5 {
		score += 1
	}

	if features.SuspiciousSections > 0 {
		score += 2
	}

	if features.HasDebugInfo == 0 && features.HasRelocations == 0 {
		score += 1
	}

	if features.WritableExecutableSections > 0 {
		score += 2
	}

	if features.FileSize > 50000 && features.ASCIIStringCount < 10 {
		score += 1
	}

	if score >= 5 {
		features.PackedIndicator = 1
	}
}

func calculateBytesEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make([]int, 256)
	for _, b := range data {
		counts[b]++
	}
	ent := 0.0
	total := float64(len(data))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		ent -= p * math.Log2(p)
	}
	return ent
}

func calculateStringEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	ent := 0.0
	total := float64(len(s))
	for _, c := range counts {
		p := float64(c) / total
		ent -= p * math.Log2(p)
	}
	return ent
}

func analyzeELF(f *os.File, features *BinaryFeatures) error {
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		return err
	}

	if ef.Class == elf.ELFCLASS64 {
		features.Is64Bit = 1
	}
	features.SectionCount = maxI(features.SectionCount, len(ef.Sections))

	if syms, err := ef.DynamicSymbols(); err == nil {
		imports := 0
		for _, s := range syms {
			if s.Section == elf.SHN_UNDEF {
				imports++
			}
		}
		features.ImportCount = maxI(features.ImportCount, imports)
	}

	return nil
}

func analyzeMachO(f *os.File, features *BinaryFeatures) error {
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}

	if fat, err := macho.NewFatFile(f); err == nil {
		if len(fat.Arches) > 0 {
			features.Is64Bit = 1
			features.SectionCount = maxI(features.SectionCount, len(fat.Arches[0].File.Sections))
		}
		return nil
	}

	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	mf, err := macho.NewFile(f)
	if err != nil {
		return err
	}

	if (mf.Cpu & 0x01000000) != 0 {
		features.Is64Bit = 1
	}
	features.SectionCount = maxI(features.SectionCount, len(mf.Sections))
	return nil
}

func analyzeZipPath(path string, features *BinaryFeatures, depth int) error {
	if depth > MaxZipRecursionDepth {
		return nil
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer zr.Close()

	return analyzeZipFiles(zr.File, features, depth)
}

func analyzeZipFiles(files []*zip.File, features *BinaryFeatures, depth int) error {
	totalRead := int64(0)
	entries := 0

	for _, zf := range files {
		if zf == nil {
			continue
		}
		if entries >= MaxZipEntries {
			break
		}
		entries++

		if zf.FileInfo().IsDir() {
			continue
		}

		rc, err := zf.Open()
		if err != nil {
			continue
		}

		limit := int64(MaxZipMemberBytes)
		lr := &io.LimitedReader{R: rc, N: limit}
		data, _ := io.ReadAll(lr)
		_ = rc.Close()

		n := int64(len(data))
		if n <= 0 {
			continue
		}
		totalRead += n
		if totalRead > MaxZipTotalBytesRead {
			break
		}

		_ = extractStringsFromBytes(data, features)

		ent := calculateBytesEntropy(data)
		if ent > features.Entropy {
			features.Entropy = ent
		}

		br := bytes.NewReader(data)

		k := detectKind(br, int64(len(data)))
		switch k {
		case kindPE:
			pf, err := pe.NewFile(br)
			if err == nil {
				tmp := &BinaryFeatures{
					FileSize:          int64(len(data)),
					MinSectionEntropy: 8.0,
				}
				_ = extractPEFeatures(pf, tmp, nil)
				mergeMemberIntoContainer(features, tmp)
				_ = pf.Close()
			}
		case kindELF:
			if ef, err := elf.NewFile(br); err == nil {
				tmp := &BinaryFeatures{FileSize: int64(len(data)), MinSectionEntropy: 8.0}
				if ef.Class == elf.ELFCLASS64 {
					tmp.Is64Bit = 1
				}
				tmp.SectionCount = len(ef.Sections)
				if syms, err := ef.DynamicSymbols(); err == nil {
					imports := 0
					for _, s := range syms {
						if s.Section == elf.SHN_UNDEF {
							imports++
						}
					}
					tmp.ImportCount = imports
				}
				mergeMemberIntoContainer(features, tmp)
			}
		case kindMachO:
			if mf, err := macho.NewFile(br); err == nil {
				tmp := &BinaryFeatures{FileSize: int64(len(data)), MinSectionEntropy: 8.0}
				if (mf.Cpu & 0x01000000) != 0 {
					tmp.Is64Bit = 1
				}
				tmp.SectionCount = len(mf.Sections)
				mergeMemberIntoContainer(features, tmp)
			}
		case kindZip:
			if depth < MaxZipRecursionDepth {
				if r, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
					_ = analyzeZipFiles(r.File, features, depth+1)
				}
			}
		default:
		}
	}

	return nil
}

func mergeMemberIntoContainer(dst, src *BinaryFeatures) {
	if dst == nil || src == nil {
		return
	}

	dst.Is64Bit = maxI(dst.Is64Bit, src.Is64Bit)
	dst.IsDLL = maxI(dst.IsDLL, src.IsDLL)

	dst.SectionCount = maxI(dst.SectionCount, src.SectionCount)
	dst.ImportCount = maxI(dst.ImportCount, src.ImportCount)
	dst.ExportCount = maxI(dst.ExportCount, src.ExportCount)
	dst.UniqueDLLCount = maxI(dst.UniqueDLLCount, src.UniqueDLLCount)
	dst.SuspiciousAPIs = maxI(dst.SuspiciousAPIs, src.SuspiciousAPIs)
	dst.SuspiciousDLLs = maxI(dst.SuspiciousDLLs, src.SuspiciousDLLs)

	dst.HasASLR = maxI(dst.HasASLR, src.HasASLR)
	dst.HasDEP = maxI(dst.HasDEP, src.HasDEP)
	dst.HasNXCompat = maxI(dst.HasNXCompat, src.HasNXCompat)
	dst.HasCFG = maxI(dst.HasCFG, src.HasCFG)
	dst.HasSEH = maxI(dst.HasSEH, src.HasSEH)
	dst.IsSigned = maxI(dst.IsSigned, src.IsSigned)

	dst.HasResources = maxI(dst.HasResources, src.HasResources)
	dst.HasTLS = maxI(dst.HasTLS, src.HasTLS)
	dst.HasRelocations = maxI(dst.HasRelocations, src.HasRelocations)

	dst.PackedIndicator = maxI(dst.PackedIndicator, src.PackedIndicator)
	dst.WritableExecutableSections = maxI(dst.WritableExecutableSections, src.WritableExecutableSections)
	dst.SuspiciousSections = maxI(dst.SuspiciousSections, src.SuspiciousSections)
	dst.LowImportCount = maxI(dst.LowImportCount, src.LowImportCount)

	dst.CodeSectionEntropy = maxF(dst.CodeSectionEntropy, src.CodeSectionEntropy)
	dst.DataSectionEntropy = maxF(dst.DataSectionEntropy, src.DataSectionEntropy)
	dst.MaxSectionEntropy = maxF(dst.MaxSectionEntropy, src.MaxSectionEntropy)
	dst.MinSectionEntropy = minFNonZero(dst.MinSectionEntropy, src.MinSectionEntropy)
	dst.AvgSectionEntropy = maxF(dst.AvgSectionEntropy, src.AvgSectionEntropy)
	dst.SectionEntropyStdDev = maxF(dst.SectionEntropyStdDev, src.SectionEntropyStdDev)

	dst.CodeToDataRatio = maxF(dst.CodeToDataRatio, src.CodeToDataRatio)
	dst.ImportToExportRatio = maxF(dst.ImportToExportRatio, src.ImportToExportRatio)
	dst.ResourceSizeRatio = maxF(dst.ResourceSizeRatio, src.ResourceSizeRatio)

	dst.SectionNameEntropy = maxF(dst.SectionNameEntropy, src.SectionNameEntropy)

	if src.CompileTimestamp > dst.CompileTimestamp {
		dst.CompileTimestamp = src.CompileTimestamp
		dst.TimestampAge = src.TimestampAge
	}
}

func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func minFNonZero(a, b float64) float64 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func peEntryPointRVA(peFile *pe.File) uint32 {
	if peFile == nil || peFile.OptionalHeader == nil {
		return 0
	}
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return oh.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		return oh.AddressOfEntryPoint
	default:
		return 0
	}
}

func rvaInSection(rva uint32, s *pe.Section) bool {
	if s == nil {
		return false
	}
	start := s.VirtualAddress
	size := maxU32(s.VirtualSize, s.Size)
	if size == 0 {
		return false
	}
	if rva < start {
		return false
	}
	return (rva - start) < size
}
