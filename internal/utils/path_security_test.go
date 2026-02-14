package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 测试内容：验证 SecureJoin 在基路径内拼接时返回合法路径。
func TestSecureJoin_AllowsWithinBase(t *testing.T) {
	base := t.TempDir()

	got, err := SecureJoin(base, filepath.Join("a", "b", "c.txt"))
	if err != nil {
		t.Fatalf("SecureJoin returned 错误: %v", err)
	}

	baseAbs, _ := filepath.Abs(base)
	if !strings.HasPrefix(strings.ToLower(got), strings.ToLower(baseAbs+string(os.PathSeparator))) && !strings.EqualFold(got, baseAbs) {
		t.Fatalf("期望 joined path to be under base, got=%q base=%q", got, baseAbs)
	}
}

// 测试内容：验证 SecureJoin 拒绝绝对路径输入。
func TestSecureJoin_RejectsAbsoluteInput(t *testing.T) {
	base := t.TempDir()
	abs := filepath.Join(base, "x.txt")

	_, err := SecureJoin(base, abs)
	if err == nil {
		t.Fatalf("期望返回错误 for absolute input path")
	}
}

// 测试内容：验证 SecureJoin 拒绝目录穿越导致的越界路径。
func TestSecureJoin_RejectsTraversalOutsideBase(t *testing.T) {
	base := t.TempDir()
	_, err := SecureJoin(base, filepath.Join("..", "escape.txt"))
	if err == nil {
		t.Fatalf("期望返回错误 for traversal")
	}
}

// 测试内容：验证不存在路径不会触发符号链接错误。
func TestEnsurePathNotSymlink_NonExistentOK(t *testing.T) {
	p := filepath.Join(t.TempDir(), "does-not-exist")
	if err := EnsurePathNotSymlink(p); err != nil {
		t.Fatalf("期望为 nil for non-existent path, got: %v", err)
	}
}

// 测试内容：验证目标在基路径外时返回错误。
func TestEnsureNoSymlinkBetween_RejectsOutsideBase(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()

	if err := EnsureNoSymlinkBetween(base, outside); err == nil {
		t.Fatalf("期望返回错误 when target is outside base")
	}
}

// 测试内容：验证 Windows 跨盘符路径会被拒绝。
func TestEnsureNoSymlinkBetween_RejectsCrossVolumeOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-specific")
	}

	base := t.TempDir()
	// 不同盘符即视为不同卷，即使该盘不存在。
	target := `Z:\somewhere`
	if err := EnsureNoSymlinkBetween(base, target); err == nil {
		t.Fatalf("期望 cross-volume 错误")
	}
}
