#!/usr/bin/env bash
# 构建全部平台产物。Windows 用 Go 1.20：最后一个支持 Windows 7/8 的 Go 版本。
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p outputs audit/data
export CGO_ENABLED=0

# IP 库只保留一份源文件，构建前同步给 n-trace 的 embed 使用。
cp -f data/ip2region_v4.xdb.gz audit/data/ip2region_v4.xdb.gz

# Sysmon 安装包按系统版本内置进 Windows 产物：
#   win7  = 10.2（Server 2008 / 2008 R2、Win7）
#   win81 = 13.30（Server 2012 / 2012 R2、Win8 / 8.1）
#   win10 = 15.0（Windows 10 及以上，含 ARM64）
mkdir -p audit/data/sysmon/win7 audit/data/sysmon/win81 audit/data/sysmon/win10
cp -f "sysmon/sysmon-10.2-win7/Sysmon.exe" audit/data/sysmon/win7/Sysmon.exe
cp -f "sysmon/sysmon-10.2-win7/Sysmon64.exe" audit/data/sysmon/win7/Sysmon64.exe
cp -f "sysmon/sysmon-13.30-win7-win2008/Sysmon.exe" audit/data/sysmon/win81/Sysmon.exe
cp -f "sysmon/sysmon-13.30-win7-win2008/Sysmon64.exe" audit/data/sysmon/win81/Sysmon64.exe
cp -f "sysmon/sysmon-15.0-win10-win11/Sysmon.exe" audit/data/sysmon/win10/Sysmon.exe
cp -f "sysmon/sysmon-15.0-win10-win11/Sysmon64.exe" audit/data/sysmon/win10/Sysmon64.exe
cp -f "sysmon/sysmon-15.0-win10-win11/Sysmon64a.exe" audit/data/sysmon/win10/Sysmon64a.exe

# Windows 清单资源（requireAdministrator + comctl32 v6）临时复制进包目录，
# 避免 go test 也被清单要求提权。
copied_rsrc=""
for f in audit/uiwin/rsrc/rsrc_windows_*.syso; do
  [ -e "$f" ] || continue
  cp -f "$f" audit/
  copied_rsrc="$copied_rsrc audit/$(basename "$f")"
done
cleanup_rsrc() {
  for f in $copied_rsrc; do rm -f "$f"; done
}
trap cleanup_rsrc EXIT

go120="${GO120:-$(go env GOPATH)/bin/go1.20.14}"
if ! "$go120" version >/dev/null 2>&1; then
  echo "缺少 Go 1.20：go install golang.org/dl/go1.20.14@latest && \"$go120\" download" >&2
  exit 1
fi

build() {
  local gobin=$1 os=$2 arch=$3 out=$4 src=$5
  local ldflags="-s -w"
  if [ "$os" = windows ]; then
    # 双击直接进原生窗口，不弹控制台；运行日志写入 n-trace-data/trace-audit.log。
    ldflags="$ldflags -H=windowsgui"
  fi
  GOOS=$os GOARCH=$arch "$gobin" build -trimpath -ldflags="$ldflags" -o "outputs/$out" "$src"
  echo "OK $out"
}

# trace-audit 依赖纯 Go 的 SQLite，只支持 64 位平台。
build "$go120" windows amd64 n-trace_windows_amd64.exe ./audit
build "$go120" windows arm64 n-trace_windows_arm64.exe ./audit
build go        darwin  amd64 n-trace_darwin_amd64 ./audit
build go        darwin  arm64 n-trace_darwin_arm64 ./audit
build go        linux   amd64 n-trace_linux_amd64 ./audit
echo "done"
