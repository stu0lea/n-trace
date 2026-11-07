package main

import "time"

// nativeConfig 是原生界面与现有后端之间的最小接线。
type nativeConfig struct {
	db       *DB
	dataDir  string
	channel  string
	interval time.Duration
	quiet    bool
	loc      *time.Location
	config   appConfig
}
