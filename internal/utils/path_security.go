package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SecureJoin 将相对路径安全拼接到 basePath 下。
//
// 说明：
// 禁止传入绝对路径，避免绕过基目录。
// 规范化并校验相对路径，拒绝 ".." 越界。
// 结果路径必须位于 basePath 内。
// 检查路径链路中是否存在符号链接，防止 symlink 穿透。
//
// 返回值为目标的绝对路径，可直接用于后续文件读写。
func SecureJoin(basePath, relativePath string) (string, error) {
	// 将基目录转换为绝对路径，避免后续相对路径比较产生歧义。
	baseAbs, err := filepath.Abs(basePath)
	if err != nil {
		return "", fmt.Errorf("路径解析失败: %w", err)
	}

	// 规范化用户传入的相对路径（折叠 .、..、重复分隔符等）。
	cleanRel := filepath.Clean(relativePath)
	if cleanRel == "." {
		// "当前目录" 语义等价于空相对路径，统一为 "" 便于后续拼接。
		cleanRel = ""
	}
	// 明确拒绝绝对路径输入，避免绕过 baseAbs 直接访问任意位置。
	if filepath.IsAbs(cleanRel) {
		return "", fmt.Errorf("非法路径: 不允许绝对路径")
	}

	// 在基目录下拼接并转为绝对路径，得到最终候选目标路径。
	targetAbs, err := filepath.Abs(filepath.Join(baseAbs, cleanRel))
	if err != nil {
		return "", fmt.Errorf("路径解析失败: %w", err)
	}

	// 统一调用 EnsureNoSymlinkBetween
	// 内部已包含 ensureWithinBase 边界校验
	// 同时完成 base->target 链路的符号链接检查
	if err := EnsureNoSymlinkBetween(baseAbs, targetAbs); err != nil {
		return "", err
	}

	return targetAbs, nil
}

// EnsurePathNotSymlink 检查指定路径节点本身是否是符号链接。
//
// 说明：
// 路径会先转为绝对路径后再检查。
// 若路径不存在，返回 nil（便于用于“即将创建”的目录场景）。
// 若路径存在且是符号链接，返回错误。
func EnsurePathNotSymlink(path string) error {
	// 将输入路径转换为绝对路径，避免不同工作目录导致判断不一致。
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("路径解析失败: %w", err)
	}

	// 使用 Lstat 检查路径节点本体，确保能识别“该节点本身是符号链接”的情况。
	info, err := os.Lstat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("检查路径失败: %w", err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("检测到符号链接穿透风险: %s", absPath)
	}

	return nil
}

// EnsureNoSymlinkBetween 检查 basePath 到 targetPath 之间的路径链路是否安全。
//
// 校验规则：
// targetPath 必须位于 basePath 内。
// 从 targetPath 逐级向上回溯到 basePath 的过程中，所有“已存在”的节点都不能是符号链接。
// 对不存在的节点不报错（方便用于即将创建的新目录/文件）。
//
// 该方法可用于上传前、删除前等关键文件操作前的防穿透校验。
func EnsureNoSymlinkBetween(basePath, targetPath string) error {
	// 统一为绝对路径，确保后续链路回溯与比较稳定可靠。
	baseAbs, err := filepath.Abs(basePath)
	if err != nil {
		return fmt.Errorf("路径解析失败: %w", err)
	}
	// 统一为绝对路径，确保后续链路回溯与比较稳定可靠。
	targetAbs, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("路径解析失败: %w", err)
	}

	if err := ensureWithinBase(baseAbs, targetAbs); err != nil {
		return err
	}

	// 从目标路径开始，逐级向上检查到基目录为止。
	current := targetAbs
	for {
		// 使用 Lstat 检查当前节点本身：若是符号链接会被识别出来。
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("检测到符号链接穿透风险: %s", current)
			}
		} else if !os.IsNotExist(statErr) {
			return fmt.Errorf("检查路径失败: %w", statErr)
		}

		if samePath(current, baseAbs) {
			break
		}

		// 取父目录，继续沿着路径链路向上回溯。
		parent := filepath.Dir(current)
		if samePath(parent, current) {
			return fmt.Errorf("非法路径: 无法定位到安全基目录")
		}
		// 移动到父目录，进行下一轮检查。
		current = parent
	}

	return nil
}

// ensureWithinBase 判断 targetAbs 是否严格位于 baseAbs 目录树内。
//
// 说明：
// Windows 下先校验卷标（盘符）一致，防止跨盘绕过。
// 通过 filepath.Rel 判断相对路径是否以 ".." 开头。
//
// 这是所有路径安全校验的基础边界检查。
func ensureWithinBase(baseAbs, targetAbs string) error {
	// 获取基目录所在卷标。
	baseVol := filepath.VolumeName(baseAbs)
	// 获取目标路径所在卷标。
	targetVol := filepath.VolumeName(targetAbs)
	if baseVol != "" || targetVol != "" {
		if !strings.EqualFold(baseVol, targetVol) {
			return fmt.Errorf("非法路径: 路径跨磁盘卷")
		}
	}

	// 计算 target 相对 base 的路径，用于判断是否越界。
	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return fmt.Errorf("非法路径: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("非法路径: 目标超出基目录")
	}
	return nil
}

// samePath 判断两个路径是否指向同一路径。
//
// 在 Windows 上使用不区分大小写比较（如 C:\Data 与 c:\data 视为相同），
// 其他系统使用区分大小写比较。
func samePath(a, b string) bool {
	// 先规范化路径字符串，消除尾分隔符、重复分隔符等差异。
	a = filepath.Clean(a)
	// 先规范化路径字符串，消除尾分隔符、重复分隔符等差异。
	b = filepath.Clean(b)
	if runtime.GOOS == "windows" {
		// Windows 文件系统通常大小写不敏感，采用不区分大小写比较。
		return strings.EqualFold(a, b)
	}
	// 其他平台按大小写敏感语义做精确比较。
	return a == b
}
