package tun

import (
	"fmt"
	opt "github.com/alibaba/kt-connect/pkg/kt/command/options"
	"github.com/alibaba/kt-connect/pkg/kt/util"
	"github.com/rs/zerolog/log"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	tunLog "github.com/xjasonlyu/tun2socks/v2/log"
	"os"
	"os/signal"
	"syscall"
)

// ToSocks create a tun and connect to socks endpoint
func (s *Cli) ToSocks(sockAddr string) error {
	tunSignal := make(chan error)
	logLevel := "warning"
	if opt.Get().Global.Debug {
		logLevel = "debug"
	}
	go func() {
		// 新建虚拟网卡设备 tunXX, tunXX这张虚拟网卡的代理设置为sockAddr即socks5代理地址
		var key = new(engine.Key)
		key.Proxy = sockAddr
		key.Device = fmt.Sprintf("tun://%s", s.GetName())
		key.LogLevel = logLevel
		tunLog.SetOutput(util.BackgroundLogger)
		engine.Insert(key)
		tunSignal <- engine.Start()

		defer func() {
			// 清理tun设备
			if err := engine.Stop(); err != nil {
				log.Error().Err(err).Msgf("Stop tun device %s failed", key.Device)
			} else {
				log.Info().Msgf("Tun device %s stopped", key.Device)
			}
		}()
		// hang住等待 ctrl-c 或者 -9 系统信号
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
	}()
	return <-tunSignal
}
