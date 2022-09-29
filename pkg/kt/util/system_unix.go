//go:build !windows

package util

import (
	"os"
)

func IsRunAsAdmin() bool {
	// 通过uid判断是否用root用户启动
	return os.Geteuid() == 0
}

func GetAdminUserName() string {
	return "root"
}
