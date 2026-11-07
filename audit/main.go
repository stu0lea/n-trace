// Trace-Audit 网络连接审计工具：导入 Sysmon 事件日志，在本地网页里查看全部网络连接。
//
// 用法:
//
//	trace-audit                     启动界面（自动打开浏览器）
//	trace-audit logs\               导入目录下的 .evtx 后启动
//	trace-audit -addr 127.0.0.1:8899 a.evtx b.evtx

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

const version = "0.1.0"

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "监听地址，端口 0 表示随机分配")
	dataDir := flag.String("data", "", "数据目录（默认使用程序同目录下的 trace-audit-data）")
	geoPath := flag.String("geo", "", "外部 ip2region_v4.xdb 路径（默认使用内置库）")
	noOpen := flag.Bool("no-open", false, "启动后不自动打开浏览器")
	quiet := flag.Bool("q", false, "不打印导入摘要")
	channel := flag.String("channel", defaultChannel, "实时采集的日志通道")
	liveInterval := flag.Duration("live-interval", time.Second, "实时采集轮询间隔")
	liveWarmup := flag.Int("live-warmup", 2000, "启动时补读的最近进程/DNS 事件数，0 表示不补读")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Trace-Audit - Sysmon 网络连接审计\n\n用法: %s [选项] <file.evtx|目录>...\n\n选项:\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()
	printBanner()

	dir := *dataDir
	if dir == "" {
		dir = defaultDataDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
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
		fmt.Printf("  数据库：%v 条连接，%v 条 DNS\n", m["conns"], m["dns"])
	}

	if flag.NArg() > 0 {
		stats, err := db.Import(flag.Args())
		if err != nil {
			log.Fatalf("导入失败: %v", err)
		}
		if !*quiet {
			fmt.Printf("  导入完成：%d 个文件，%d 条事件，%d 条连接，%d 条 DNS，耗时 %s\n",
				len(stats.Files), stats.Events, stats.Conns, stats.DNS, stats.Took)
		}
	}

	token := newToken()
	srv := &server{db: db, token: token, loc: time.Local,
		dataDir: dir, channel: *channel, interval: *liveInterval, warmup: *liveWarmup}

	// 有 Sysmon 日志就自动实时采集，不需要额外参数。
	// 判定分四种情况：服务 + 日志都在才算装好；有服务没日志自动卸载重装；没服务则提示安装。
	liveOn := false
	if err := liveSupported(); err == nil {
		svc, hasLog := sysmonServiceInstalled(), channelExists(*channel)
		switch {
		case svc && hasLog:
			liveOn = srv.enableLive()
			fmt.Println("检测到 Sysmon 日志，已自动开启实时采集")
		case svc:
			fmt.Println("检测到 Sysmon 服务但日志通道缺失，正在自动卸载并重新安装…")
			if _, err := sysmonReinstall(dir); err != nil {
				fmt.Printf("自动重装失败: %v\n", err)
			} else {
				liveOn = srv.enableLive()
				fmt.Println("Sysmon 已重新安装，已开启实时采集")
			}
		default:
			if !*quiet && promptInstallSysmon(dir) {
				liveOn = srv.enableLive()
			}
		}
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	url := fmt.Sprintf("http://%s/?t=%s", humanAddr(ln.Addr()), token)
	fmt.Println("  " + strings.Repeat("-", 68))
	fmt.Printf("  界面地址 : %s\n", url)
	fmt.Printf("  数据目录 : %s\n", dir)
	if liveOn {
		fmt.Println("  实时采集 : 已开启")
	} else {
		fmt.Println("  实时采集 : 未开启")
	}
	fmt.Println("  按 Ctrl+C 退出")
	fmt.Println("  " + strings.Repeat("-", 68))

	if !*noOpen {
		openBrowser(url)
	}

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		db.Close()
		os.Exit(0)
	}()

	if err := http.Serve(ln, srv.routes()); err != nil {
		log.Fatal(err)
	}
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
		d := filepath.Join(filepath.Dir(exe), "trace-audit-data")
		if err := os.MkdirAll(d, 0o755); err == nil {
			return d
		}
	}
	if c, err := os.UserCacheDir(); err == nil {
		return filepath.Join(c, "trace-audit")
	}
	return "trace-audit-data"
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
		fmt.Printf("请手动打开浏览器访问上面的地址\n")
	}
}
