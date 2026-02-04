//go:build !embed

package main

import (
	"io/fs"
)

// GetFrontendAssets 纯后端模式返回 nil
// 编译时 不带 tags 就会走这里
func GetFrontendAssets() fs.FS {
	return nil
}
