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

//go:embed uiwin/sysmon-dns.xml
var sysmonDNSConfigXML string

const (
	sysmonChannel = defaultChannel
	defaultLogMax = int64(2) << 30 // 2 GiB
)

// SysmonStatus 供界面展示 Sysmon 安装状态与日志信息。
type SysmonStatus struct {
	Supported      bool   `json:"supported"`
	Installed      bool   `json:"installed"`
	ServiceExists  bool   `json:"serviceExists"`
	ServiceName    string `json:"serviceName,omitempty"`
	ServiceRunning bool   `json:"serviceRunning"`
	Channel        string `json:"channel"`
	ChannelExists  bool   `json:"channelExists"`
	LogPath        string `json:"logPath"`
	LogBytes       int64  `json:"logBytes"`
	MaxBytes       int64  `json:"maxBytes"`
	Admin          bool   `json:"admin"`
	OSVersion      string `json:"osVersion"`
	Arch           string `json:"arch"`
	Package        string `json:"package"`
	PackageFile    string `json:"packageFile"`
	ArgsText       string `json:"argsText"`
	EffectiveArgs  string `json:"effectiveArgs"`
	DNSSupported   bool   `json:"dnsSupported"`
	DNSEnabled     bool   `json:"dnsEnabled"`
	Error          string `json:"error,omitempty"`
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
		Admin: isAdmin(), Arch: archLabel(),
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
	st.ServiceRunning = sysmonServiceRunning(st.ServiceName)
	st.ChannelExists = channelExists(sysmonChannel)
	st.Installed = st.ServiceExists && st.ChannelExists
	st.LogPath, st.LogBytes = sysmonLogFile()
	if st.ChannelExists {
		st.MaxBytes = sysmonMaxSize()
	}
	return st
}

func sysmonServiceRunning(name string) bool {
	if name == "" {
		return false
	}
	out, err := runHidden("sc", "query", name)
	return err == nil && strings.Contains(strings.ToUpper(decodeWinText(out)), "RUNNING")
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
	appPrintf("[Sysmon] 执行: wevtutil sl %s /ms:%d", sysmonChannel, bytes)
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

// supportsDNS 判断系统是否有 DNS Client ETW 遥测（Windows 8.1+）。
func supportsDNS(v winVersionInfo) bool {
	return v.Major > 6 || (v.Major == 6 && v.Minor >= 3)
}

// sysmonEffectiveArgs 返回按 DNS 开关调整后的完整安装参数（预览用，不落盘）。
func sysmonEffectiveArgs(dataDir string, dns bool) string {
	return composeSysmonArgs(sysmonArgsText(dataDir), dns, dataDir)
}

const dnsConfigName = "sysmon-dns.xml"

// sysmonArgsText 返回保存的完整安装参数（config.ini 的 sysmon_args）；
// 未配置时按 DNS 开关组装默认值并写回。
func sysmonArgsText(dataDir string) string {
	cfg := loadAppConfig(dataDir)
	if text := strings.TrimSpace(cfg.SysmonArgs); text != "" {
		return text
	}
	text := composeSysmonArgs("", sysmonDNSEnabled(dataDir), dataDir)
	cfg.SysmonArgs = text
	_ = cfg.save(dataDir)
	return text
}

// composeSysmonArgs 组装完整安装参数：
// -accepteula -i [DNS配置路径] -n（extra 仅用于旧版参数迁移）。
// 不勾选 DNS 时裸 -i：Sysmon 内置默认配置本身就会记录进程创建与退出（EID 1/5）。
func composeSysmonArgs(extra string, dns bool, dataDir string) string {
	args, err := splitArgs(extra)
	if err != nil {
		args = nil
	}
	clean := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "-accepteula" {
			continue
		}
		if args[i] == "-i" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
			continue
		}
		clean = append(clean, args[i])
	}
	out := []string{"-accepteula", "-i"}
	if dns {
		out = append(out, filepath.Join(dataDir, dnsConfigName))
	}
	out = append(out, clean...)
	if !hasSysmonFlag(clean, "-n") {
		out = append(out, "-n")
	}
	return strings.Join(out, " ")
}

// hasSysmonFlag 判断参数里是否已包含某个开关（兼容 -x=true 写法）。
func hasSysmonFlag(args []string, flag string) bool {
	for _, a := range args {
		key := a
		if j := strings.Index(a, "="); j > 0 {
			key = a[:j]
		}
		if key == flag {
			return true
		}
	}
	return false
}

// dnsConfigPath 返回数据目录下的 DNS 配置完整路径。
func dnsConfigPath(dataDir string) string {
	return filepath.Join(dataDir, dnsConfigName)
}

// sysmonDNSEnabled 读取 DNS 开关（config.ini 的 sysmon_dns_enabled，默认开启；
// 旧版本存在 sysmon-dns.txt 时读取并迁移）。仅对支持的系统生效。
func sysmonDNSEnabled(dataDir string) bool {
	legacy := filepath.Join(dataDir, "sysmon-dns.txt")
	if _, err := os.Stat(legacy); err == nil {
		on := true
		if b, rerr := os.ReadFile(legacy); rerr == nil {
			on = strings.TrimSpace(string(b)) != "0"
		}
		cfg := loadAppConfig(dataDir)
		cfg.SysmonDNSEnabled = on
		_ = cfg.save(dataDir)
		_ = os.Remove(legacy)
		return on
	}
	return loadAppConfig(dataDir).SysmonDNSEnabled
}

func sysmonSetDNS(dataDir string, on bool) error {
	cfg := loadAppConfig(dataDir)
	cfg.SysmonDNSEnabled = on
	// DNS 开关联动安装参数：勾选时自动补上 sysmon-dns.xml 路径，取消时自动移除。
	cfg.SysmonArgs = composeSysmonArgs(sysmonArgsText(dataDir), on, dataDir)
	if err := cfg.save(dataDir); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dataDir, "sysmon-dns.txt"))
	return nil
}

// sysmonSetArgs 校验并保存完整安装参数（写入 config.ini 的 sysmon_args）。
func sysmonSetArgs(dataDir, text string) (string, error) {
	if err := validateSysmonArgs(text); err != nil {
		return "", err
	}
	cfg := loadAppConfig(dataDir)
	cfg.SysmonArgs = strings.TrimSpace(text)
	if err := cfg.save(dataDir); err != nil {
		return "", fmt.Errorf("保存参数失败: %v", err)
	}
	return cfg.SysmonArgs, nil
}

// writeDNSConfig 生成最小配置：打开进程创建/退出、网络连接与 DNS 查询。
// （自定义配置会整体替换 Sysmon 默认规则集，所以进程退出必须显式写出。）
//
// 注意两个坑：
//  1. 配置是整体替换规则集，不是追加；
//  2. 空的 <NetworkConnect onmatch="include"/> 表示「只记录匹配的规则」，没有规则就一条都不记，
//     要全量必须用 onmatch="exclude" 且不带子规则（排除 0 条 = 全收）。
func writeDNSConfig(dataDir string) (string, error) {
	p := filepath.Join(dataDir, dnsConfigName)
	if err := os.WriteFile(p, []byte(sysmonDNSConfigXML), 0o644); err != nil {
		return "", fmt.Errorf("写入 Sysmon 配置失败: %v", err)
	}
	return p, nil
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

// validateSysmonArgs 校验完整安装参数：允许固定部分（-accepteula/-i 配置路径）
// 和应急常用开关，避免误传 -u 等卸载控制参数。
func validateSysmonArgs(text string) error {
	if len(text) > 512 {
		return fmt.Errorf("参数过长（最多 512 字符）")
	}
	args, err := splitArgs(text)
	if err != nil {
		return err
	}
	// -i 的配置路径是可选的（裸 -i 用默认配置安装），其余带值开关仍要求有值。
	needValue := map[string]bool{"-h": true, "-a": true, "-g": true, "-k": true, "-d": true, "-z": true}
	optionalValue := map[string]bool{"-i": true}
	allowed := map[string]bool{
		"-accepteula": true, "-i": true, "-n": true, "-l": true, "-h": true, "-a": true,
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
		} else if optionalValue[key] && !strings.Contains(t, "=") {
			// -i 后跟非 "-" 开头的 token 时视为配置路径。
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
		}
	}
	if !hasSysmonFlag(args, "-n") {
		return fmt.Errorf("缺少 -n（网络连接 EID 3），网络审计会失效")
	}
	return nil
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

func installSysmonPackage(dataDir, dir, exe string, useDNS bool) (string, error) {
	dest, err := releaseSysmonBinary(dataDir, dir, exe)
	if err != nil {
		return "", err
	}
	var logs []string
	addLog := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			logs = append(logs, s)
		}
	}
	// 安装参数按 DNS 开关组装：Win8.1+ 且勾选 DNS 时带一份最小配置（进程创建/
	// 退出/网络连接/DNS 查询全收）；未勾选则裸 -i -n 按内置默认配置安装，
	// 默认配置本身就会记录进程退出（EID 5）。Win7 没有 DNS 遥测，同裸 -i -n。
	var argv []string
	if dir == "win7" || !supportsDNS(windowsVersionInfo()) {
		argv = []string{"-accepteula", "-i", "-n"}
	} else {
		dnsOn := sysmonDNSEnabled(dataDir)
		dnsArgs, derr := splitArgs(sysmonEffectiveArgs(dataDir, dnsOn))
		if derr != nil {
			dnsArgs = []string{"-accepteula", "-i", "-n"}
		}
		argv = dnsArgs
		if dnsOn {
			if _, err := writeDNSConfig(dataDir); err != nil {
				return "", err
			}
		}
	}
	appPrintf("[Sysmon] 执行: %s %s", exe, strings.Join(argv, " "))
	addLog("> " + exe + " " + strings.Join(argv, " "))
	out, err := runHidden(dest, argv...)
	addLog(decodeWinText(out))
	printSysmonOut(out)
	if err != nil {
		return strings.Join(logs, "\r\n"),
			fmt.Errorf("%s 安装失败: %v %s", sysmonPackageLabel(dir), err, tailText(out))
	}
	if err := sysmonSetLogSize(defaultLogMax); err != nil {
		return strings.Join(logs, "\r\n"), fmt.Errorf("安装完成，但设置日志上限失败: %v", err)
	}
	// 把当前生效的规则打印出来，便于确认配置真的生效（配置是整体替换，不是追加）。
	if dump, e := runHidden(dest, "-c"); e == nil {
		if s := strings.TrimSpace(decodeWinText(dump)); s != "" {
			appPrintf("[Sysmon] 当前配置:\n%s", indentText(s, "  "))
			addLog("> " + exe + " -c")
			addLog(s)
		}
	}
	return strings.Join(logs, "\r\n"), nil
}

// sysmonInstall 按当前系统选择安装包，执行 -accepteula -i -n 并把上限设为 2GB。
func sysmonInstall(dataDir string) (string, error) {
	if !isAdmin() {
		return "", fmt.Errorf("需要管理员权限，请以管理员身份重新运行")
	}
	var logs []string
	addLog := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			logs = append(logs, s)
		}
	}
	joined := func() string { return strings.Join(logs, "\r\n") }
	// 服务已存在就先卸载，避免 -i 在残留服务上直接失败（首次安装时这里不会触发）。
	if svc := installedSysmonService(); svc != "" {
		out, err := sysmonUninstall(dataDir)
		addLog(out)
		if err != nil {
			return joined(), fmt.Errorf("卸载已有服务 %s 失败: %v", svc, err)
		}
	}
	v := windowsVersionInfo()
	dir, exe, err := sysmonPackageFor(v)
	if err != nil {
		return joined(), err
	}
	out, err := installSysmonPackage(dataDir, dir, exe, true)
	addLog(out)
	if err != nil && dir == "win10" && runtime.GOARCH == "amd64" {
		// 某些机器上 64 位包的清单注册会被安全软件拦截；先从最简单的 64 位参数重试，
		// 再回退到用户实测可用的 32 位 Sysmon.exe。
		appPrintf("[Sysmon] 64 位安装失败，去掉 DNS 配置重试：%v", err)
		out2, e2 := installSysmonPackage(dataDir, dir, exe, false)
		addLog(out2)
		if e2 == nil {
			addLog("已安装 Sysmon 15.0（64 位，未启用 DNS 配置）")
			return joined(), nil
		} else {
			appPrintf("[Sysmon] 64 位重试仍失败，回退 32 位：%v", e2)
		}
		out3, e3 := installSysmonPackage(dataDir, "win10", "Sysmon.exe", false)
		addLog(out3)
		if e3 == nil {
			addLog("已回退安装 32 位 Sysmon 15.0（64 位包注册失败）")
			return joined(), nil
		}
	}
	// 个别 32 位 Win10 装不上新版时，退回 10.2 再试一次。
	if err != nil && runtime.GOARCH == "386" && dir == "win10" {
		out2, e2 := installSysmonPackage(dataDir, "win7", "Sysmon.exe", false)
		addLog(out2)
		if e2 == nil {
			addLog("Sysmon 15.0 安装失败，已回退安装 Sysmon 10.2")
			return joined(), nil
		}
	}
	// 2012/2012 R2、Win8/8.1 缺 SHA-2 补丁时 13.30 装不上，同样退回 10.2（这些系统没有 DNS 遥测）。
	if err != nil && dir == "win81" {
		fallback := "Sysmon.exe"
		if runtime.GOARCH != "386" {
			fallback = "Sysmon64.exe"
		}
		out2, e2 := installSysmonPackage(dataDir, "win7", fallback, false)
		addLog(out2)
		if e2 == nil {
			addLog("Sysmon 13.30 安装失败（可能缺少 SHA-2 补丁 KB4474419），已回退安装 Sysmon 10.2")
			return joined(), nil
		}
	}
	if err != nil {
		return joined(), err
	}
	addLog(fmt.Sprintf("已安装 %s（%s）", sysmonPackageLabel(dir), exe))
	return joined(), nil
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
		appPrintf("[Sysmon] 执行: %s -u force", filepath.Base(bin))
		if out, err := runHiddenInput(bin, "y\n", "-u", "force"); err == nil {
			printSysmonOut(out)
			return tailText(out), nil
		} else {
			printSysmonOut(out)
			last = tailText(out)
		}
		appPrintf("[Sysmon] 执行: %s -u", filepath.Base(bin))
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

// printSysmonOut 把 Sysmon 的原始输出按行缩进写入运行日志。
func printSysmonOut(b []byte) {
	if s := strings.TrimSpace(decodeWinText(b)); s != "" {
		appPrintf("[Sysmon] 输出:\n%s", indentText(s, "  "))
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
		appPrintf("当前系统 Windows %s 暂不支持自动安装 Sysmon：%v", v.Str, err)
		return false
	}
	appPrintf("当前系统 Windows %s（%s），将安装 %s / %s", v.Str, archLabel(), sysmonPackageLabel(dir), exe)
	if !isAdmin() {
		appPrintln("安装 Sysmon 需要管理员权限，请右键以管理员身份重新运行；也可稍后在界面「采集」页安装。")
		return false
	}
	if !stdinIsTerminal() {
		appPrintln("未检测到 Sysmon 日志，可在界面「采集」页安装。")
		return false
	}
	appPrint("是否现在安装 Sysmon 并开启实时采集？[y/N] ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "是":
	default:
		appPrintln("已跳过安装，可在界面「采集」页稍后安装。")
		return false
	}
	if out, err := sysmonInstall(dataDir); err != nil {
		appPrintf("安装失败: %v\n%s", err, out)
		return false
	}
	appPrintln("Sysmon 安装完成，日志上限已设为 2 GB")
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
	s := strings.TrimSpace(decodeWinText(b))
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
