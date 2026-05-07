package sql

import (
	"io/fs"
	"strings"
	"testing"
)

// TestUpdateFS_AllFilesEmbedded 验证 27 个 update 文件都被 go:embed 嵌入。
// 任何一个 .sql 文件被开发者意外漏命/重命名都会让这个测试挂。
func TestUpdateFS_AllFilesEmbedded(t *testing.T) {
	fsys := UpdateFS()

	var sqlFiles []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".sql") {
			sqlFiles = append(sqlFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embed FS: %v", err)
	}

	// 当前 V0.2.2: 15 张表 + 11 个 INSERT seed = 26 个
	// （11 = 1 main tenant + 1 platform_admin role + 9 perms; 第 27 个是 cross join grant，所以 27 个）
	const expected = 27
	if len(sqlFiles) != expected {
		t.Errorf("update/ 嵌入文件数不对: got %d, want %d\nfiles:\n  %s",
			len(sqlFiles), expected, strings.Join(sqlFiles, "\n  "))
	}

	// 抽样检查文件名格式（避免命错名导致 migration runner 拒跑）
	for _, p := range sqlFiles {
		base := p[strings.LastIndex(p, "/")+1:]
		if !strings.HasPrefix(base, "update-") {
			t.Errorf("文件名不以 update- 开头: %s", p)
		}
	}
}
