package main

import (
	"time"
)

// cleanupBatchSize 每批删除的行数；小批次避免长事务阻塞实时采集与查询。
const cleanupBatchSize = 5000

// StartRetention 启动后台保留清理：启动后执行一次，之后每 6 小时执行一次。
// daysFn 每轮执行前读取最新配置，便于界面修改后无需重启生效；返回 0 表示不清理。
func (d *DB) StartRetention(daysFn func() int, logf func(string, ...interface{})) {
	go func() {
		for {
			if days := daysFn(); days > 0 {
				if n, err := d.CleanupRetention(days, logf); err != nil {
					logf("数据保留清理失败: %v", err)
				} else if n > 0 {
					logf("数据保留清理完成：删除 %d 条超过 %d 天的记录", n, days)
				}
			}
			time.Sleep(6 * time.Hour)
		}
	}()
}

// CleanupRetention 分批删除超过保留期的历史数据（conn/dns 明细及派生的
// process_list/process_ip 聚合），并回收磁盘空间。
func (d *DB) CleanupRetention(days int, logf func(string, ...interface{})) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -days).UnixMilli()
	var total int64

	// conn：先按批删除，同时维护全文索引；'delete' 命令不可用（旧版 SQLite）时退回整体重建。
	ftsOK := true
	for {
		rows, err := d.sql.Query(
			`SELECT id,image,cmdline,dst_host,geo,dst_ip FROM conn WHERE ts<? LIMIT ?`,
			cutoff, cleanupBatchSize)
		if err != nil {
			return total, err
		}
		type ftsRow struct {
			id                                  int64
			image, cmdline, dstHost, geo, dstIP string
		}
		var batch []ftsRow
		for rows.Next() {
			var r ftsRow
			if err := rows.Scan(&r.id, &r.image, &r.cmdline, &r.dstHost, &r.geo, &r.dstIP); err != nil {
				rows.Close()
				return total, err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return total, err
		}
		if len(batch) == 0 {
			break
		}
		tx, err := d.sql.Begin()
		if err != nil {
			return total, err
		}
		if ftsOK {
			for _, r := range batch {
				if _, err := tx.Exec(`INSERT INTO conn_fts(conn_fts,rowid,image,cmdline,dst_host,geo,dst_ip)
					VALUES('delete',?,?,?,?,?,?)`,
					r.id, r.image, r.cmdline, r.dstHost, r.geo, r.dstIP); err != nil {
					ftsOK = false // 索引里留下少量孤儿 rowid 不影响结果，兜底走整体重建
					break
				}
			}
		}
		res, err := tx.Exec(`DELETE FROM conn WHERE id IN (
			SELECT id FROM conn WHERE ts<? LIMIT ?)`, cutoff, cleanupBatchSize)
		if err != nil {
			tx.Rollback()
			return total, err
		}
		if err := tx.Commit(); err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if len(batch) < cleanupBatchSize {
			break
		}
	}
	if !ftsOK {
		logf("全文索引需重建…")
		if err := d.rebuildFTS(); err != nil {
			return total, err
		}
	}

	// dns 明细：直接按批删。
	for _, table := range []string{"dns"} {
		for {
			res, err := d.sql.Exec(`DELETE FROM `+table+` WHERE id IN (
				SELECT id FROM `+table+` WHERE ts<? LIMIT ?)`, cutoff, cleanupBatchSize)
			if err != nil {
				return total, err
			}
			n, _ := res.RowsAffected()
			total += n
			if n < cleanupBatchSize {
				break
			}
		}
	}

	// 进程聚合表：最后一次活动时间超过保留期才删除；再清掉失去引用的 IP 关联。
	res, err := d.sql.Exec(`DELETE FROM process_list
		WHERE coalesce(nullif(end_ts,0), nullif(last_ts,0), start_ts) < ?`, cutoff)
	if err != nil {
		return total, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		total += n
		if _, err := d.sql.Exec(`DELETE FROM process_ip
			WHERE guid NOT IN (SELECT guid FROM process_list)`); err != nil {
			return total, err
		}
	}

	d.reclaimSpace(logf)
	return total, nil
}

// reclaimSpace 回收删除后的磁盘空间：老库（auto_vacuum 未开启）先整库压缩一次
// 以启用增量回收，之后每次清理只做增量回收和 WAL 截断。
func (d *DB) reclaimSpace(logf func(string, ...interface{})) {
	var av int
	_ = d.sql.QueryRow(`PRAGMA auto_vacuum`).Scan(&av)
	if av == 0 {
		logf("正在压缩数据库（首次清理，启用空间自动回收）…")
		if _, err := d.sql.Exec(`VACUUM`); err != nil {
			logf("数据库压缩失败（正在采集时属正常，将在下轮重试）: %v", err)
			return
		}
		logf("数据库压缩完成")
		return
	}
	_, _ = d.sql.Exec(`PRAGMA incremental_vacuum(10000)`)
	_, _ = d.sql.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
}
