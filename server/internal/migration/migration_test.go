package migration

import (
	"testing"
)

func TestFilePattern_AcceptsValidNames(t *testing.T) {
	cases := []string{
		"update-20260504.1__create_table_x.sql",
		"update-20260504.27__grant_admin.sql",
		"update-20991231.999__abc.sql",
		"update-20260504.01__zero_padded.sql",
		"update-20260504.5.sql", // 描述可选
	}
	for _, name := range cases {
		if !filePattern.MatchString(name) {
			t.Errorf("应当匹配但没匹配: %s", name)
		}
	}
}

func TestFilePattern_RejectsInvalidNames(t *testing.T) {
	cases := []string{
		"update-2026050.1__short_date.sql", // 7 位日期
		"update-2026050a.1__nonnumeric.sql",
		"insert-20260504.1__wrong_prefix.sql",
		"update-20260504.sql",  // 缺序号
		"update-20260504.1.sql.bak", // 错误后缀
		"random.sql",
	}
	for _, name := range cases {
		if filePattern.MatchString(name) {
			t.Errorf("应当拒绝但匹配了: %s", name)
		}
	}
}

func TestParseSortAndCheck_OrdersAndDeduplicates(t *testing.T) {
	files := []*sqlFile{
		{filename: "update-20260504.10__a.sql"},
		{filename: "update-20260504.2__b.sql"},
		{filename: "update-20260601.1__c.sql"},
		{filename: "update-20260504.1__d.sql"},
	}
	sorted := parseSortAndCheck(files)
	if sorted == nil {
		t.Fatal("parseSortAndCheck 返回 nil（不该有冲突）")
	}
	want := []string{"20260504.1", "20260504.2", "20260504.10", "20260601.1"}
	for i, f := range sorted {
		if f.versionIndex != want[i] {
			t.Errorf("位置 %d: got %s, want %s", i, f.versionIndex, want[i])
		}
	}
}

func TestParseSortAndCheck_DetectsConflict(t *testing.T) {
	files := []*sqlFile{
		{filename: "update-20260504.1__a.sql"},
		{filename: "update-20260504.1__b.sql"}, // 同日同序号 → 冲突
	}
	if parseSortAndCheck(files) != nil {
		t.Error("应当检测冲突返回 nil")
	}
}

func TestParseSortAndCheck_ZeroPaddingSameAsUnpadded(t *testing.T) {
	// .01 和 .1 都解析为 sequence=1 → 视为冲突
	files := []*sqlFile{
		{filename: "update-20260504.1__a.sql"},
		{filename: "update-20260504.01__b.sql"},
	}
	if parseSortAndCheck(files) != nil {
		t.Error("0-padded 与 unpadded 同序号应当算冲突")
	}
}

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		date int
		seq  int
	}{
		{"20260504.27", 20260504, 27},
		{"20260504.1", 20260504, 1},
		{"invalid", 0, 0},
	}
	for _, c := range cases {
		d, s := parseVersion(c.in)
		if d != c.date || s != c.seq {
			t.Errorf("parseVersion(%q) = (%d, %d), want (%d, %d)",
				c.in, d, s, c.date, c.seq)
		}
	}
}

func TestStripComments(t *testing.T) {
	in := `-- 行注释
/* 块
   注释 */
INSERT INTO x VALUES (1);
-- 尾注释`
	out := stripComments(in)
	// 注释应被剥掉，INSERT 保留
	if !contains(out, "INSERT INTO x") {
		t.Errorf("INSERT 不应被剥掉, got: %q", out)
	}
	if contains(out, "行注释") || contains(out, "块") || contains(out, "尾注释") {
		t.Errorf("注释应当被剥掉, got: %q", out)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
