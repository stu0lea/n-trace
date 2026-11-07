package main

import (
	"fmt"
	"strings"
)

// 启动横幅使用纯 ASCII，避免 Win7 控制台字体缺字。
const banner = ` _____ ____      _    ____ _____        _   _   _ ____ ___ _____ 
|_   _|  _ \    / \  / ___| ____|      / \ | | | |  _ \_ _|_   _|
  | | | |_) |  / _ \| |   |  _| _____ / _ \| | | | | | | |  | |  
  | | |  _ <  / ___ \ |___| |__|_____/ ___ \ |_| | |_| | |  | |  
  |_| |_| \_\/_/   \_\____|_____|   /_/   \_\___/|____/___| |_|  `

func printBanner() {
	fmt.Println(banner)
	fmt.Println("  Sysmon 网络连接审计  ·  Trace-Audit " + version)
	fmt.Println("  " + strings.Repeat("=", 68))
}
