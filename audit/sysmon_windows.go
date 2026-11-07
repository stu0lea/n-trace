//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// 内置三份 Sysmon 安装包：
//
//	win7  = Sysmon 10.2：Server 2008 / 2008 R2、Win7（x86 + x64）
//	win81 = Sysmon 13.30：Server 2012 / 2012 R2、Win8 / 8.1（x86 + x64）
//	win10 = Sysmon 15.0：Windows 10 及以上（x86 + x64 + ARM64）
//
//go:embed data/sysmon/win7/Sysmon.exe data/sysmon/win7/Sysmon64.exe data/sysmon/win81/Sysmon.exe data/sysmon/win81/Sysmon64.exe data/sysmon/win10/Sysmon.exe data/sysmon/win10/Sysmon64.exe data/sysmon/win10/Sysmon64a.exe
var sysmonBins embed.FS

const (
	sysmonChannel = defaultChannel
	defaultLogMax = int64(2) << 30 // 2 GiB
)

// SysmonStatus 供界面展示 Sysmon 安装状态与日志信息。
type SysmonStatus struct {
	Supported     bool   `json:"supported"`
	Installed     bool   `json:"installed"`
	ServiceExists bool   `json:"serviceExists"`
	ServiceName   string `json:"serviceName,omitempty"`
	Channel       string `json:"channel"`
	ChannelExists bool   `json:"channelExists"`
	LogPath       string `json:"logPath"`
	LogBytes      int64  `json:"logBytes"`
	MaxBytes      int64  `json:"maxBytes"`
	Admin         bool   `json:"admin"`
	OSVersion     string `json:"osVersion"`
	Arch          string `json:"arch"`
	Package       string `json:"package"`
	PackageFile   string `json:"packageFile"`
	ArgsText      string `json:"argsText"`
	EffectiveArgs string `json:"effectiveArgs"`
	DNSSupported  bool   `json:"dnsSupported"`
	DNSEnabled    bool   `json:"dnsEnabled"`
	Error         string `json:"error,omitempty"`
}

// channelExists 判断指定日志通道是否已存在（即 Sysmon 已安装并注册）。
func channelExists(channel string) bool {
	_, err := runWevt("gl", channel)
	return err == nil
}

func sysmonStatus(dataDir string) SysmonStatus {
	v := windowsVersionInfo()
	dir, exe, pkgErr := sysmonPackageFor(v)
	st := SysmonStatus{
		Supported: true, Channel: sysmonChannel, OSVersion: v.Str,
		Admin: isAdmin(), Arch: archLabel(), ArgsText: sysmonArgsText(dataDir),
		DNSSupported: supportsDNS(v),
	}
	st.DNSEnabled = st.DNSSupported && sysmonDNSEnabled(dataDir)
	st.EffectiveArgs = sysmonEffectiveArgs(dataDir, st.DNSEnabled)
	if pkgErr == nil {
		st.Package = sysmonPackageLabel(dir)
		st.PackageFile = exe
	} else {
		st.Error = pkgErr.Error()
	}
	// 已安装 = 服务在 + 日志通道在，两个条件缺一都算没装好（残留服务或残留 evtx 都不算）。
	st.ServiceName = installedSysmonService()
	st.ServiceExists = st.ServiceName != ""
	st.ChannelExists = channelExists(sysmonChannel)
	st.Installed = st.ServiceExists && st.ChannelExists
	st.LogPath, st.LogBytes = sysmonLogFile()
	if st.ChannelExists {
		st.MaxBytes = sysmonMaxSize()
	}
	return st
}

// sysmonLogFile 返回 Sysmon 日志文件路径与当前大小。
func sysmonLogFile() (string, int64) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	p := filepath.Join(root, "System32", "winevt", "Logs", "Microsoft-Windows-Sysmon%4Operational.evtx")
	if fi, err := os.Stat(p); err == nil {
		return p, fi.Size()
	}
	return p, 0
}

// sysmonMaxSize 读取通道当前的最大日志大小（字节）。
func sysmonMaxSize() int64 {
	out, err := runWevt("gl", sysmonChannel)
	if err != nil {
		return 0
	}
	re := regexp.MustCompile(`(?i)max\s*size\s*[:：]\s*(\d+)`)
	if m := re.FindStringSubmatch(string(out)); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		return n
	}
	re = regexp.MustCompile(`最大[^:：]*[:：]\s*(\d+)`)
	if m := re.FindStringSubmatch(string(out)); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		return n
	}
	return 0
}

// sysmonSetLogSize 调整 Sysmon 日志上限。
func sysmonSetLogSize(bytes int64) error {
	if bytes < 64<<20 || bytes > 64<<30 {
		return fmt.Errorf("日志大小需在 64MB 到 64GB 之间")
	}
	fmt.Printf("[Sysmon] 执行: wevtutil sl %s /ms:%d\n", sysmonChannel, bytes)
	if _, err := runWevt("sl", sysmonChannel, "/ms:"+strconv.FormatInt(bytes, 10)); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------- 版本选择

// sysmonPackageFor 按系统版本与 CPU 架构选择内置安装包。
//
//	Server 2008 / 2008 R2、Win7（6.0 / 6.1）        -> Sysmon 10.2（13.30 需要 SHA-2 补丁，老机器装不上）
//	Server 2012 / 2012 R2、Win8 / 8.1（6.2 / 6.3）  -> Sysmon 13.30（15.0 要求 Windows 10+）
//	Windows 10 及以上                                -> Sysmon 15.0
func sysmonPackageFor(v winVersionInfo) (dir, exe string, err error) {
	switch runtime.GOARCH {
	case "386":
		exe = "Sysmon.exe"
	case "amd64":
		exe = "Sysmon64.exe"
	case "arm64":
		exe = "Sysmon64a.exe"
	default:
		return "", "", fmt.Errorf("不支持的 CPU 架构: %s", runtime.GOARCH)
	}
	if v.Major < 6 {
		return "", "", fmt.Errorf("不支持的系统版本 Windows %s", v.Str)
	}
	if runtime.GOARCH == "arm64" {
		if v.Major == 6 {
			return "", "", fmt.Errorf("ARM64 仅支持 Windows 8 及以上系统")
		}
		return "win10", exe, nil
	}
	if runtime.GOARCH == "386" {
		exe = "Sysmon.exe"
	} else {
		exe = "Sysmon64.exe"
	}
	if v.Major == 6 && v.Minor <= 1 {
		return "win7", exe, nil
	}
	if v.Major == 6 {
		return "win81", exe, nil
	}
	return "win10", exe, nil
}

func sysmonPackageLabel(dir string) string {
	switch dir {
	case "win10":
		return "Sysmon 15.0（Windows 10 及以上）"
	case "win81":
		return "Sysmon 13.30（Win8 / Server 2012 及以上）"
	default:
		return "Sysmon 10.2（Server 2008 / Win7）"
	}
}

func archLabel() string {
	switch runtime.GOARCH {
	case "386":
		return "32 位"
	case "arm64":
		return "ARM64"
	default:
		return "64 位"
	}
}

const defaultExtraArgs = "-n"

// sysmonArgsText 返回用户保存的附加安装参数（不含固定的 -accepteula -i）。
// 旧版本保存的 -dns 会被移除：DNS 参数由程序按系统版本自动添加。
func sysmonArgsText(dataDir string) string {
	b, err := os.ReadFile(filepath.Join(dataDir, "sysmon-args.txt"))
	if err != nil {
		return defaultExtraArgs
	}
	args, err := splitArgs(string(b))
	if err != nil {
		return defaultExtraArgs
	}
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != "-dns" {
			out = append(out, a)
		}
	}
	return strings.Join(out, " ")
}

// supportsDNS 判断系统是否有 DNS Client ETW 遥测（Windows 8.1+）。
func supportsDNS(v winVersionInfo) bool {
	return v.Major > 6 || (v.Major == 6 && v.Minor >= 3)
}

// sysmonEffectiveArgs 返回实际下发的完整安装参数，供界面展示。
func sysmonEffectiveArgs(dataDir string, dns bool) string {
	parts := []string{"-accepteula", "-i"}
	if dns {
		cfg := filepath.Join(dataDir, dnsConfigName)
		if strings.ContainsAny(cfg, " \t") {
			cfg = `"` + cfg + `"`
		}
		parts = append(parts, cfg)
	}
	extra := sysmonExtraArgs(dataDir)
	if !hasSysmonFlag(extra, "-n") {
		extra = append(extra, "-n")
	}
	parts = append(parts, extra...)
	return strings.Join(parts, " ")
}

const dnsConfigName = "sysmon-dns.xml"

// sysmonDNSEnabled 读取 DNS 开关，默认开启（仅对支持的系统生效）。
func sysmonDNSEnabled(dataDir string) bool {
	b, err := os.ReadFile(filepath.Join(dataDir, "sysmon-dns.txt"))
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(b)) != "0"
}

func sysmonSetDNS(dataDir string, on bool) error {
	v := "1"
	if !on {
		v = "0"
	}
	return os.WriteFile(filepath.Join(dataDir, "sysmon-dns.txt"), []byte(v+"\n"), 0o644)
}

// writeDNSConfig 生成最小配置：打开进程创建、网络连接与 DNS 查询。
//
// 注意两个坑：
//  1. 配置是整体替换规则集，不是追加；
//  2. 空的 <NetworkConnect onmatch="include"/> 表示「只记录匹配的规则」，没有规则就一条都不记，
//     要全量必须用 onmatch="exclude" 且不带子规则（排除 0 条 = 全收）。
func writeDNSConfig(dataDir string) (string, error) {
	xml := `<Sysmon schemaversion="4.50">
  <EventFiltering>
    <ProcessCreate onmatch="exclude"/>
    <NetworkConnect onmatch="exclude"/>
    <DnsQuery onmatch="exclude"/>
  </EventFiltering>
</Sysmon>
`
	p := filepath.Join(dataDir, dnsConfigName)
	if err := os.WriteFile(p, []byte(xml), 0o644); err != nil {
		return "", fmt.Errorf("写入 DNS 配置失败: %v", err)
	}
	return p, nil
}

// sysmonSetArgs 校验并保存附加安装参数。
func sysmonSetArgs(dataDir, text string) (string, error) {
	text, err := normalizeSysmonArgs(text)
	if err != nil {
		return "", err
	}
	if err := validateSysmonArgs(text); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dataDir, "sysmon-args.txt"), []byte(text+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("保存参数失败: %v", err)
	}
	return text, nil
}

// normalizeSysmonArgs 去掉界面里手写的固定参数（-accepteula/-i/-dns），只保留附加选项。
// 界面输入框展示的是完整命令行，保存时统一剥离，避免重复下发或误带配置路径。
func normalizeSysmonArgs(text string) (string, error) {
	args, err := splitArgs(strings.TrimSpace(text))
	if err != nil {
		return "", err
	}
	out := make([]string, 0, len(args))
	needValue := map[string]bool{"-h": true, "-a": true, "-g": true, "-k": true, "-d": true, "-z": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			// 配置路径、参数值的残留片段（例如带空格的 -i 路径被拆开），直接丢弃。
			continue
		}
		key := a
		if j := strings.Index(a, "="); j > 0 {
			key = a[:j]
		}
		switch key {
		case "-accepteula", "-dns":
			continue
		case "-i":
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
			continue
		}
		out = append(out, a)
		if needValue[key] && !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			out = append(out, args[i+1])
			i++
		}
	}
	return strings.Join(out, " "), nil
}

// splitArgs 按空白拆分参数，支持双引号包裹含空格的值。
func splitArgs(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuote, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			has = true
		case (r == ' ' || r == '\t') && !inQuote:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		case r == '\n' || r == '\r':
			return nil, fmt.Errorf("参数不能包含换行")
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if inQuote {
		return nil, fmt.Errorf("引号未闭合")
	}
	if has {
		out = append(out, cur.String())
	}
	return out, nil
}

// validateSysmonArgs 只允许应急常用开关，避免误传 -i/-u 等安装控制参数。
func validateSysmonArgs(text string) error {
	if len(text) > 512 {
		return fmt.Errorf("参数过长（最多 512 字符）")
	}
	args, err := splitArgs(text)
	if err != nil {
		return err
	}
	needValue := map[string]bool{"-h": true, "-a": true, "-g": true, "-k": true, "-d": true, "-z": true}
	allowed := map[string]bool{
		"-n": true, "-l": true, "-h": true, "-a": true,
		"-g": true, "-k": true, "-d": true, "-z": true, "-r": true, "-t": true,
	}
	for i := 0; i < len(args); i++ {
		t := args[i]
		if !strings.HasPrefix(t, "-") {
			return fmt.Errorf("参数 %q 缺少对应的开关", t)
		}
		key := t
		if j := strings.Index(t, "="); j > 0 {
			key = t[:j]
		}
		if key == "-dns" {
			return fmt.Errorf("Sysmon 没有 -dns 开关，DNS 请用界面上的「启用 DNS 日志」开关")
		}
		if !allowed[key] {
			return fmt.Errorf("不允许使用参数 %q", t)
		}
		if needValue[key] && !strings.Contains(t, "=") {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return fmt.Errorf("参数 %s 需要一个值", key)
			}
			i++
		}
	}
	return nil
}

// sysmonExtraArgs 返回保存的附加参数，解析失败时退回默认值。
func sysmonExtraArgs(dataDir string) []string {
	text := sysmonArgsText(dataDir)
	args, err := splitArgs(text)
	if err != nil {
		args, _ = splitArgs(defaultExtraArgs)
	}
	return args
}

// releaseSysmonBinary 把指定安装包释放到数据目录并返回路径。
func releaseSysmonBinary(dataDir, dir, exe string) (string, error) {
	bin, err := sysmonBins.ReadFile("data/sysmon/" + dir + "/" + exe)
	if err != nil {
		return "", fmt.Errorf("内置安装包读取失败: %v", err)
	}
	destDir := filepath.Join(dataDir, "sysmon")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(destDir, exe)
	if err := os.WriteFile(dest, bin, 0o755); err != nil {
		return "", fmt.Errorf("释放安装包失败: %v", err)
	}
	return dest, nil
}

func installSysmonPackage(dataDir, dir, exe string) error {
	dest, err := releaseSysmonBinary(dataDir, dir, exe)
	if err != nil {
		return err
	}
	// 固定 -accepteula -i，附加参数由界面保存。
	// Win8.1+ 有 DNS Client ETW，安装时带一份只开 DnsQuery 的最小配置来采集 EID 22；
	// Sysmon 没有 -dns 命令行开关（Win7 上更是没有 DNS 遥测）。
	argv := []string{"-accepteula", "-i"}
	// 10.2 没有 DnsQuery 事件（schema 上限 4.21），带配置会直接装不上。
	if dir != "win7" && supportsDNS(windowsVersionInfo()) && sysmonDNSEnabled(dataDir) {
		cfg, err := writeDNSConfig(dataDir)
		if err != nil {
			return err
		}
		argv = append(argv, cfg)
	}
	extra := sysmonExtraArgs(dataDir)
	if !hasSysmonFlag(extra, "-n") {
		// 没有 -n 就没有 EID 3，网络连接审计会失效，这里兜底补上。
		extra = append(extra, "-n")
	}
	argv = append(argv, extra...)
	fmt.Printf("[Sysmon] 执行: %s %s\n", exe, strings.Join(argv, " "))
	out, err := runHidden(dest, argv...)
	printSysmonOut(out)
	if err != nil {
		return fmt.Errorf("%s 安装失败: %v %s", sysmonPackageLabel(dir), err, tailText(out))
	}
	if err := sysmonSetLogSize(defaultLogMax); err != nil {
		return fmt.Errorf("安装完成，但设置日志上限失败: %v", err)
	}
	// 把当前生效的规则打印出来，便于确认配置真的生效（配置是整体替换，不是追加）。
	if dump, e := runHidden(dest, "-c"); e == nil {
		if s := strings.TrimSpace(string(dump)); s != "" {
			fmt.Printf("[Sysmon] 当前配置:\n%s\n", indentText(s, "  "))
		}
	}
	return nil
}

// hasSysmonFlag 判断参数里是否已包含某个开关（兼容 -x=true 写法）。
func hasSysmonFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

// sysmonInstall 按当前系统选择安装包，执行 -accepteula -i -n 并把上限设为 2GB。
func sysmonInstall(dataDir string) (string, error) {
	if !isAdmin() {
		return "", fmt.Errorf("需要管理员权限，请以管理员身份重新运行")
	}
	// 服务已存在就先卸载，避免 -i 在残留服务上直接失败（首次安装时这里不会触发）。
	if svc := installedSysmonService(); svc != "" {
		if _, err := sysmonUninstall(dataDir); err != nil {
			return "", fmt.Errorf("卸载已有服务 %s 失败: %v", svc, err)
		}
	}
	v := windowsVersionInfo()
	dir, exe, err := sysmonPackageFor(v)
	if err != nil {
		return "", err
	}
	err = installSysmonPackage(dataDir, dir, exe)
	// 个别 32 位 Win10 装不上新版时，退回 10.2 再试一次。
	if err != nil && runtime.GOARCH == "386" && dir == "win10" {
		if e2 := installSysmonPackage(dataDir, "win7", "Sysmon.exe"); e2 == nil {
			return "Sysmon 15.0 安装失败，已回退安装 Sysmon 10.2", nil
		}
	}
	// 2012/2012 R2、Win8/8.1 缺 SHA-2 补丁时 13.30 装不上，同样退回 10.2（这些系统没有 DNS 遥测）。
	if err != nil && dir == "win81" {
		fallback := "Sysmon.exe"
		if runtime.GOARCH != "386" {
			fallback = "Sysmon64.exe"
		}
		if e2 := installSysmonPackage(dataDir, "win7", fallback); e2 == nil {
			return "Sysmon 13.30 安装失败（可能缺少 SHA-2 补丁 KB4474419），已回退安装 Sysmon 10.2", nil
		}
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("已安装 %s（%s）", sysmonPackageLabel(dir), exe), nil
}

// sysmonUninstall 卸载已安装的 Sysmon 服务。
func sysmonUninstall(dataDir string) (string, error) {
	if !isAdmin() {
		return "", fmt.Errorf("需要管理员权限，请以管理员身份重新运行")
	}
	svc := installedSysmonService()
	if svc == "" {
		return "", fmt.Errorf("未检测到已安装的 Sysmon 服务")
	}
	var bins []string
	if p := serviceBinaryPath(svc); p != "" {
		bins = append(bins, p)
	}
	v := windowsVersionInfo()
	if dir, exe, err := sysmonPackageFor(v); err == nil {
		if dest, err := releaseSysmonBinary(dataDir, dir, exe); err == nil {
			bins = append(bins, dest)
		}
		if dir == "win10" {
			if dest, err := releaseSysmonBinary(dataDir, "win7", "Sysmon64.exe"); err == nil {
				bins = append(bins, dest)
			}
		}
	}
	if len(bins) == 0 {
		return "", fmt.Errorf("找不到可用的 Sysmon 卸载程序")
	}
	var last string
	for _, bin := range bins {
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		fmt.Printf("[Sysmon] 执行: %s -u force\n", filepath.Base(bin))
		if out, err := runHiddenInput(bin, "y\n", "-u", "force"); err == nil {
			printSysmonOut(out)
			return tailText(out), nil
		} else {
			printSysmonOut(out)
			last = tailText(out)
		}
		fmt.Printf("[Sysmon] 执行: %s -u\n", filepath.Base(bin))
		if out, err := runHiddenInput(bin, "y\n", "-u"); err == nil {
			printSysmonOut(out)
			return tailText(out), nil
		} else {
			printSysmonOut(out)
			last = tailText(out)
		}
	}
	return last, fmt.Errorf("卸载失败，请确认以管理员身份运行")
}

// printSysmonOut 把 Sysmon 的原始屏幕输出按行缩进打到控制台。
func printSysmonOut(b []byte) {
	if s := strings.TrimSpace(string(b)); s != "" {
		fmt.Printf("[Sysmon] 输出:\n%s\n", indentText(s, "  "))
	}
}

// sysmonReinstall 与安装同一条路径：有服务先卸载，再按当前系统安装。
func sysmonReinstall(dataDir string) (string, error) { return sysmonInstall(dataDir) }

func installedSysmonService() string {
	for _, name := range []string{"Sysmon64", "Sysmon"} {
		if _, err := runHidden("sc", "query", name); err == nil {
			return name
		}
	}
	return ""
}

// sysmonServiceInstalled 判断 Sysmon 服务是否已注册（与日志通道是否存在无关）。
func sysmonServiceInstalled() bool { return installedSysmonService() != "" }

// serviceBinaryPath 从 sc qc 输出里取服务可执行文件路径。
func serviceBinaryPath(svc string) string {
	out, err := runHidden("sc", "qc", svc)
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`(?im)^\s*BINARY_PATH_NAME\s*:\s*(.+)$`)
	m := re.FindStringSubmatch(string(out))
	if m == nil {
		return ""
	}
	p := strings.TrimSpace(m[1])
	if strings.HasPrefix(p, `"`) {
		if i := strings.Index(p[1:], `"`); i >= 0 {
			return p[1 : i+1]
		}
	}
	if i := strings.Index(p, " -"); i > 0 {
		p = p[:i]
	}
	return strings.TrimSpace(p)
}

// ---------------------------------------------------------------- 交互安装

// promptInstallSysmon 在交互终端里询问是否安装 Sysmon；返回是否安装成功。
func promptInstallSysmon(dataDir string) bool {
	v := windowsVersionInfo()
	dir, exe, err := sysmonPackageFor(v)
	if err != nil {
		fmt.Printf("当前系统 Windows %s 暂不支持自动安装 Sysmon：%v\n", v.Str, err)
		return false
	}
	fmt.Printf("当前系统 Windows %s（%s），将安装 %s / %s\n", v.Str, archLabel(), sysmonPackageLabel(dir), exe)
	if !isAdmin() {
		fmt.Println("安装 Sysmon 需要管理员权限，请右键以管理员身份重新运行；也可稍后在界面「采集」页安装。")
		return false
	}
	if !stdinIsTerminal() {
		fmt.Println("未检测到 Sysmon 日志，可在界面「采集」页安装。")
		return false
	}
	fmt.Print("是否现在安装 Sysmon 并开启实时采集？[y/N] ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "是":
	default:
		fmt.Println("已跳过安装，可在界面「采集」页稍后安装。")
		return false
	}
	if out, err := sysmonInstall(dataDir); err != nil {
		fmt.Printf("安装失败: %v\n%s\n", err, out)
		return false
	}
	fmt.Println("Sysmon 安装完成，日志上限已设为 2 GB")
	return true
}

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// ---------------------------------------------------------------- 命令执行

// runHidden 运行命令并隐藏控制台窗口。
func runHidden(name string, args ...string) ([]byte, error) {
	return runHiddenInput(name, "", args...)
}

func runHiddenInput(name, stdin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.Bytes(), err
}

func tailText(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 500 {
		s = s[len(s)-500:]
	}
	return s
}

// indentText 给多行输出统一加前缀，便于在控制台里区分 Sysmon 自己的输出。
func indentText(s, prefix string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------- 系统信息

type osVersionInfo struct {
	Size       uint32
	Major      uint32
	Minor      uint32
	Build      uint32
	Platform   uint32
	CSDVersion [128]uint16
}

type winVersionInfo struct {
	Major uint32
	Minor uint32
	Build uint32
	Str   string
}

// windowsVersionInfo 用 RtlGetVersion 读真实系统版本（兼容 Win7，且不受兼容性清单影响）。
func windowsVersionInfo() winVersionInfo {
	v := osVersionInfo{Size: uint32(unsafe.Sizeof(osVersionInfo{}))}
	syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion").Call(uintptr(unsafe.Pointer(&v)))
	if v.Major == 0 {
		return winVersionInfo{Major: 10, Str: "unknown"}
	}
	return winVersionInfo{Major: v.Major, Minor: v.Minor, Build: v.Build,
		Str: fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Build)}
}

// windowsVersion 返回主版本号与 "10.0.22631" 形式的版本串。
func windowsVersion() (uint32, string) {
	v := windowsVersionInfo()
	return v.Major, v.Str
}

// isAdmin 判断当前进程是否具备管理员权限。
func isAdmin() bool {
	_, err := runHidden("fltmc")
	return err == nil
}
