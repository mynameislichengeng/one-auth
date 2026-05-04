package handler

import "testing"

func TestSafeReturnTo(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// 合法的 query string
		{"client_id=admin_web&state=xyz", "client_id=admin_web&state=xyz"},
		{"", ""},
		// 防开放重定向：不允许被解析为 absolute URL
		{"//evil.com/path", ""},
		{"http://evil.com/path", ""},
		{"https://evil.com/path", ""},
		// 防 header 注入
		{"foo=bar\r\nLocation: http://evil.com", ""},
		{"foo=bar\nset-cookie: x=y", ""},
		// 边界：含 // 但不在前缀
		{"client_id=foo//bar", "client_id=foo//bar"},
	}
	for _, c := range cases {
		got := safeReturnTo(c.in)
		if got != c.want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
