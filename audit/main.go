// n-trace 网络连接审计工具：导入 Sysmon 事件日志，在原生窗口里查看全部网络连接。
//
// 用法:
//
//	n-trace                         启动原生界面（-web 可回退浏览器界面）
//	n-trace logs\                   导入目录下的 .evtx 后启动
//	n-trace -addr 127.0.0.1:8899 a.evtx b.evtx

package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const version = "1.0"

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "监听地址，端口 0 表示随机分配")
	dataDir := flag.String("data", "", "数据目录（默认使用程序同目录下的 n-trace-data）")
	geoPath := flag.String("geo", "", "外部 ip2region_v4.xdb 路径（默认使用内置库）")
	noOpen := flag.Bool("no-open", false, "启动后不自动打开浏览器")
	quiet := flag.Bool("q", false, "不打印导入摘要")
	webUI := flag.Bool("web", false, "强制使用浏览器界面（Windows 默认使用原生窗口）")
	channel := flag.String("channel", defaultChannel, "实时采集的日志通道")
	liveInterval := flag.Duration("live-interval", time.Second, "实时采集轮询间隔")
	adminTask := flag.String("admin-task", "", "内部使用：管理员任务请求文件")
	adminResult := flag.String("admin-result", "", "内部使用：管理员任务结果文件")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "N-trace 联网安全审计\n\n用法: %s [选项] <file.evtx|目录>...\n\n选项:\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	if *webUI {
		prepareWebConsole()
	}

	dir := *dataDir
	if dir == "" {
		dir = defaultDataDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}
	appCfg := loadAppConfig(dir)
	setupAppLog(dir, appCfg.LogRetentionMonths)
	printBanner()
	appPrintf("数据目录：%s", dir)
	if *adminTask != "" {
		if err := runAdminTaskFile(*adminTask, *adminResult); err != nil {
			appPrintf("管理员任务结束：%v", err)
		}
		return
	}
	if !acquireSingleInstance() {
		return
	}

	geo, err := openGeo(*geoPath)
	if err != nil {
		log.Fatalf("加载 IP 库失败: %v", err)
	}

	db, err := openDB(filepath.Join(dir, "audit.db"), geo)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer db.Close()

	if m, err := db.Meta(); err == nil && !*quiet {
		appPrintf("数据库：%v 条连接，%v 条 DNS", m["conns"], m["dns"])
	}

	if flag.NArg() > 0 {
		stats, err := db.Import(flag.Args())
		if err != nil {
			log.Fatalf("导入失败: %v", err)
		}
		if !*quiet {
			appPrintf("导入完成：%d 个文件，%d 条事件，%d 条连接，%d 条 DNS，耗时 %s",
				len(stats.Files), stats.Events, stats.Conns, stats.DNS, stats.Took)
		}
	}

	cfg := nativeConfig{
		db: db, dataDir: dir, channel: appCfg.LiveChannel,
		interval: time.Duration(appCfg.ReadIntervalSeconds) * time.Second,
		quiet:    *quiet, loc: time.Local, config: appCfg,
	}
	if runtime.GOOS == "windows" && !*webUI {
		if err := nativeRun(cfg); err != nil {
			log.Fatalf("启动原生界面失败: %v", err)
		}
		return
	}

	runWeb(db, dir, *addr, *noOpen, *quiet, *channel, *liveInterval)
}

// runWeb 启动浏览器界面，供非 Windows 平台、-web 调试参数和旧版界面使用。
func runWeb(db *DB, dataDir, addr string, noOpen, quiet bool, channel string, interval time.Duration) {
	token := newToken()
	srv := &server{db: db, token: token, loc: time.Local,
		dataDir: dataDir, channel: channel, interval: interval,
		quit: make(chan struct{}, 1)}

	// 有 Sysmon 日志就自动实时采集，不需要额外参数。
	// 判定分四种情况：服务 + 日志都在才算装好；有服务没日志自动卸载重装；没服务则提示安装。
	liveOn := false
	if err := liveSupported(); err == nil {
		svc, hasLog := sysmonServiceInstalled(), channelExists(channel)
		switch {
		case svc && hasLog:
			liveOn = srv.enableLive()
			appPrintln("检测到 Sysmon 日志，已自动开启实时采集")
		case svc:
			appPrintln("检测到 Sysmon 服务但日志通道缺失，正在自动卸载并重新安装…")
			if _, err := sysmonReinstall(dataDir); err != nil {
				appPrintf("自动重装失败: %v", err)
			} else {
				liveOn = srv.enableLive()
				appPrintln("Sysmon 已重新安装，已开启实时采集")
			}
		default:
			if !quiet && promptInstallSysmon(dataDir) {
				liveOn = srv.enableLive()
			}
		}
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	url := fmt.Sprintf("http://%s/?t=%s", humanAddr(ln.Addr()), token)
	writeWebShortcut(dataDir, url)
	defer clearWebShortcut(dataDir)
	appPrintln("  " + strings.Repeat("-", 68))
	appPrintf("界面地址 : %s", url)
	appPrintf("数据目录 : %s", dataDir)
	if liveOn {
		appPrintln("实时采集 : 已开启")
	} else {
		appPrintln("实时采集 : 未开启")
	}
	appPrintln("按 Ctrl+C 退出")
	appPrintln("  " + strings.Repeat("-", 68))

	if !noOpen {
		openBrowser(url)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- http.Serve(ln, srv.routes())
	}()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigCh:
		return
	case <-srv.quit:
		return
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Print(err)
		}
	}
}

func writeWebShortcut(dir, url string) {
	_ = os.WriteFile(filepath.Join(dir, "web-url.txt"), []byte(url+"\n"), 0o644)
	body := "[InternetShortcut]\r\nURL=" + url + "\r\n"
	_ = os.WriteFile(filepath.Join(dir, "open-n-trace.url"), []byte(body), 0o644)
}

func clearWebShortcut(dir string) {
	_ = os.Remove(filepath.Join(dir, "open-n-trace.url"))
	_ = os.Remove(filepath.Join(dir, "web-url.txt"))
}

func newToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// humanAddr 把 [::]:1234 之类换成可直接点击的地址。
func humanAddr(a net.Addr) string {
	s := a.String()
	if strings.HasPrefix(s, "[::]") || strings.HasPrefix(s, "0.0.0.0") {
		_, port, _ := net.SplitHostPort(s)
		return "127.0.0.1:" + port
	}
	return s
}

// defaultDataDir 优先放在程序目录，不可写时退到用户缓存目录。
func defaultDataDir() string {
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		d := migrateLegacyDataDir(
			filepath.Join(base, "n-trace-data"),
			filepath.Join(base, "trace-audit-data"),
		)
		if err := os.MkdirAll(d, 0o755); err == nil {
			return d
		}
	}
	if c, err := os.UserCacheDir(); err == nil {
		return filepath.Join(c, "n-trace")
	}
	return "n-trace-data"
}

func migrateLegacyDataDir(target, legacy string) string {
	if _, err := os.Stat(target); err == nil {
		return target
	}
	if _, err := os.Stat(legacy); err != nil {
		return target
	}
	if err := os.Rename(legacy, target); err == nil {
		return target
	}
	return legacy
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		appPrintf("请手动打开浏览器访问上面的地址")
	}
}
