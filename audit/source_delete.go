package main

import "fmt"

// DeleteSource 删除一个本地导入文件及其连接/DNS 数据。
func (d *DB) DeleteSource(name string) (int64, int64, error) {
	if name == "" || name == liveSource {
		return 0, 0, fmt.Errorf("不能删除实时采集源")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.sql.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	resConn, err := tx.Exec(`DELETE FROM conn WHERE source=?`, name)
	if err != nil {
		return 0, 0, err
	}
	nConn, _ := resConn.RowsAffected()
	resDNS, err := tx.Exec(`DELETE FROM dns WHERE source=?`, name)
	if err != nil {
		return 0, 0, err
	}
	nDNS, _ := resDNS.RowsAffected()
	if _, err := tx.Exec(`DELETE FROM file WHERE name=?`, name); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	if err := d.rebuildFTS(); err != nil {
		return nConn, nDNS, err
	}
	return nConn, nDNS, nil
}

func (d *DB) rebuildFTS() error {
	if _, err := d.sql.Exec(`DROP TABLE IF EXISTS conn_fts`); err != nil {
		return err
	}
	if _, err := d.sql.Exec(`CREATE VIRTUAL TABLE conn_fts USING fts5(image, cmdline, dst_host, geo, dst_ip, content='', tokenize='trigram')`); err != nil {
		return err
	}
	_, err := d.sql.Exec(`INSERT INTO conn_fts(rowid,image,cmdline,dst_host,geo,dst_ip)
		SELECT id,image,cmdline,dst_host,geo,dst_ip FROM conn`)
	return err
}
