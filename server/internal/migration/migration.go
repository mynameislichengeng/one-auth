// Package migration 自动执行 SQL 变更脚本（启动时）。
//
// 设计来自 weixin 项目的同款机制：
//   - 扫描 sqlFS 下所有 update-YYYYMMDD.N__desc.sql
//   - 按 (date, sequence) 升序，跳过已在 auto_sql_record 表登记的版本
//   - 用 MySQL GET_LOCK 防多实例并发
//   - 任一步失败：终止迁移、记 slog.Error，不阻塞 server 启动
//
// 文件命名规则与铁律见 server/sql/README.md。
package migration

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	lockName       = "oneauth_auto_sql_migration"
	lockTimeoutSec = 10

	// auto_sql_record 跑器自身用的版本登记表。
	createTableDDL = `
CREATE TABLE IF NOT EXISTS auto_sql_record (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    filename      VARCHAR(200)    NOT NULL COMMENT '完整文件名',
    version_index VARCHAR(30)     NOT NULL COMMENT '日期+序号，如 20260504.1',
    created_at    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_filename (filename),
    KEY idx_version (version_index)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='oneauth 自动 SQL 迁移版本记录'`
)

// 文件名格式：update-YYYYMMDD.N__描述.sql；描述部分可选。
var filePattern = regexp.MustCompile(`^update-(\d{8})\.(\d+)(?:__(.{1,50}))?\.sql$`)

type sqlFile struct {
	filename     string
	filePath     string
	date         int
	sequence     int
	versionIndex string // "YYYYMMDD.N"
}

// Run 执行自动迁移。enabled=false 时直接跳过；任何错误都只记 slog 不返回。
//
// db 应该是底层 *sql.DB（GORM 的 db.DB() 拿到）。
// sqlFS 应该是 server/sql/embed.go UpdateFS() 返回的 update/ 子文件系统根。
func Run(db *sql.DB, sqlFS fs.FS, enabled bool) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[AutoSqlMigration] 未预期 panic（不阻塞 server）", "err", r)
		}
	}()

	if !enabled {
		slog.Info("[AutoSqlMigration] 已关闭（migration.enabled=false），跳过")
		return
	}
	slog.Info("[AutoSqlMigration] 开始")

	if _, err := db.Exec(createTableDDL); err != nil {
		slog.Error("[AutoSqlMigration] 建 auto_sql_record 失败，跳过迁移", "err", err)
		return
	}

	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		slog.Error("[AutoSqlMigration] 取数据库连接失败，跳过迁移", "err", err)
		return
	}
	defer conn.Close()

	if !acquireLock(ctx, conn) {
		slog.Warn("[AutoSqlMigration] 获取分布式锁失败（其他实例正在迁移），跳过")
		return
	}
	defer releaseLock(ctx, conn)
	slog.Info("[AutoSqlMigration] 分布式锁获取成功", "lockName", lockName)

	doMigrate(ctx, db, sqlFS)
	slog.Info("[AutoSqlMigration] 流程结束")
}

// acquireLock 获取 MySQL 应用级锁。GET_LOCK 返回 1 表示成功。
func acquireLock(ctx context.Context, conn *sql.Conn) bool {
	var locked sql.NullInt64
	row := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", lockName, lockTimeoutSec)
	if err := row.Scan(&locked); err != nil {
		slog.Warn("[AutoSqlMigration] GET_LOCK 异常", "err", err)
		return false
	}
	return locked.Valid && locked.Int64 == 1
}

func releaseLock(ctx context.Context, conn *sql.Conn) {
	var released sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT RELEASE_LOCK(?)", lockName).Scan(&released); err != nil {
		slog.Warn("[AutoSqlMigration] RELEASE_LOCK 异常", "err", err)
	}
}

func doMigrate(ctx context.Context, db *sql.DB, sqlFS fs.FS) {
	files, err := scanSQLFiles(sqlFS)
	if err != nil {
		slog.Warn("[AutoSqlMigration] 扫描 SQL 失败，跳过", "err", err)
		return
	}
	if len(files) == 0 {
		slog.Info("[AutoSqlMigration] 未找到任何 SQL 脚本，跳过")
		return
	}
	slog.Info("[AutoSqlMigration] 扫描到文件数", "count", len(files))

	// 文件名校验：任一非法立即终止（防止开发者命错名）
	for _, f := range files {
		if !filePattern.MatchString(f.filename) {
			slog.Error("[AutoSqlMigration] 非法文件名，迁移终止",
				"filename", f.filename,
				"expected", "update-YYYYMMDD.N__desc.sql")
			return
		}
	}

	sorted := parseSortAndCheck(files)
	if sorted == nil {
		return
	}

	pending, err := filterPending(ctx, db, sorted)
	if err != nil {
		slog.Error("[AutoSqlMigration] 查询已执行记录失败，跳过", "err", err)
		return
	}
	if len(pending) == 0 {
		slog.Info("[AutoSqlMigration] 数据库已是最新版本")
		return
	}

	slog.Info("[AutoSqlMigration] 待执行脚本数", "count", len(pending))
	for i, f := range pending {
		slog.Info(fmt.Sprintf("[AutoSqlMigration] [%d/%d] 执行 %s (v=%s)",
			i+1, len(pending), f.filename, f.versionIndex))
		if err := executeSQLFile(ctx, db, f, sqlFS); err != nil {
			slog.Error("[AutoSqlMigration] 执行失败，迁移终止",
				"step", fmt.Sprintf("%d/%d", i+1, len(pending)),
				"filename", f.filename,
				"err", err)
			return
		}
	}
	slog.Info("[AutoSqlMigration] 全部执行完成", "count", len(pending))
}

// scanSQLFiles 走 sqlFS 全部 .sql 文件（递归），不解析文件名。
func scanSQLFiles(sqlFS fs.FS) ([]*sqlFile, error) {
	var files []*sqlFile
	err := fs.WalkDir(sqlFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".sql") {
			return nil
		}
		files = append(files, &sqlFile{filename: d.Name(), filePath: path})
		return nil
	})
	return files, err
}

// parseSortAndCheck 解析 (date, sequence) 字段并按其升序排，
// 检测重复版本号；返回 nil 表示有错误已记录。
func parseSortAndCheck(files []*sqlFile) []*sqlFile {
	for _, f := range files {
		m := filePattern.FindStringSubmatch(f.filename)
		// filePattern 已在上一步 MatchString 校验过，这里可放心解析
		f.date, _ = strconv.Atoi(m[1])
		f.sequence, _ = strconv.Atoi(m[2])
		f.versionIndex = m[1] + "." + strconv.Itoa(f.sequence)
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].date != files[j].date {
			return files[i].date < files[j].date
		}
		return files[i].sequence < files[j].sequence
	})
	for i := 1; i < len(files); i++ {
		prev, curr := files[i-1], files[i]
		if prev.date == curr.date && prev.sequence == curr.sequence {
			slog.Error("[AutoSqlMigration] 版本号冲突",
				"file_a", prev.filename,
				"file_b", curr.filename,
				"version", fmt.Sprintf("%d.%d", prev.date, prev.sequence))
			return nil
		}
	}
	return files
}

// filterPending 找出所有"版本号大于已执行最大版本"的文件。
// 注：用 maxVersion 比较而不是逐个查 IN（O(N) 文件 × O(M) 已执行）。
func filterPending(ctx context.Context, db *sql.DB, sorted []*sqlFile) ([]*sqlFile, error) {
	rows, err := db.QueryContext(ctx, "SELECT version_index FROM auto_sql_record")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var maxDate, maxSeq int
	hasMax := false
	executedCount := 0
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		executedCount++
		d, s := parseVersion(v)
		if !hasMax || d > maxDate || (d == maxDate && s > maxSeq) {
			maxDate, maxSeq = d, s
			hasMax = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if hasMax {
		slog.Info("[AutoSqlMigration] 已执行最大版本",
			"executed_count", executedCount,
			"max_version", fmt.Sprintf("%d.%d", maxDate, maxSeq))
	} else {
		slog.Info("[AutoSqlMigration] 无已执行记录，将执行全部脚本")
	}

	var pending []*sqlFile
	for _, f := range sorted {
		if hasMax && (f.date < maxDate || (f.date == maxDate && f.sequence <= maxSeq)) {
			continue
		}
		pending = append(pending, f)
	}
	return pending, nil
}

// executeSQLFile 读文件 → 执行 → 写记录。三步用同一 db handle，不在事务里
// （DDL 隐式提交，事务无意义）。
func executeSQLFile(ctx context.Context, db *sql.DB, f *sqlFile, sqlFS fs.FS) error {
	content, err := fs.ReadFile(sqlFS, f.filePath)
	if err != nil {
		return fmt.Errorf("读文件: %w", err)
	}
	body := strings.TrimSpace(stripComments(string(content)))
	if body == "" {
		// 仅含注释，登记跳过
		slog.Info("[AutoSqlMigration] 文件无实际 SQL（仅注释），登记跳过", "filename", f.filename)
		return recordExecuted(ctx, db, f)
	}
	if _, err := db.ExecContext(ctx, string(content)); err != nil {
		return fmt.Errorf("执行 SQL: %w", err)
	}
	return recordExecuted(ctx, db, f)
}

func recordExecuted(ctx context.Context, db *sql.DB, f *sqlFile) error {
	if _, err := db.ExecContext(ctx,
		"INSERT INTO auto_sql_record (filename, version_index) VALUES (?, ?)",
		f.filename, f.versionIndex); err != nil {
		return fmt.Errorf("登记 auto_sql_record: %w", err)
	}
	return nil
}

// stripComments 去 SQL 注释（用于判断文件是否"只有注释"）。
// 仅用于判空，不影响实际执行的 SQL 内容。
func stripComments(content string) string {
	blockRe := regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineRe := regexp.MustCompile(`--[^\n]*`)
	return lineRe.ReplaceAllString(blockRe.ReplaceAllString(content, ""), "")
}

// parseVersion 把 "20260504.27" 解析成 (20260504, 27)。
// 解析失败返回 (0, 0)，让该记录在比较中被忽略（不阻塞迁移）。
func parseVersion(v string) (date, seq int) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return 0, 0
	}
	date, _ = strconv.Atoi(parts[0])
	seq, _ = strconv.Atoi(parts[1])
	return
}
