package connect

import (
	"fmt"
	"github.com/alibaba/kt-connect/pkg/common"
	opt "github.com/alibaba/kt-connect/pkg/kt/command/options"
	"github.com/alibaba/kt-connect/pkg/kt/service/cluster"
	"github.com/alibaba/kt-connect/pkg/kt/service/sshchannel"
	"github.com/alibaba/kt-connect/pkg/kt/service/tun"
	"github.com/alibaba/kt-connect/pkg/kt/transmission"
	"github.com/alibaba/kt-connect/pkg/kt/util"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/proxy"
	"strings"
	"time"
)

func ByTun2Socks() error {
	podIP, podName, privateKeyPath, err := getOrCreateShadow()
	if err != nil {
		return err
	}

	localSshPort := util.GetRandomTcpPort()
	// port-forward localSshPort <=> common.StandardSshPort
	if _, err = transmission.SetupPortForwardToLocal(podName, common.StandardSshPort, localSshPort); err != nil {
		return err
	}
	// 启动socks5代理
	// 1. ssh root@127.0.0.1 -P ${localSshPort} <=> ssh root@127.0.0.1 -P common.StandardSshPort
	// 2. ssh tunnel => socks5 tunnel
	if err = startSocks5Connection(podIP, privateKeyPath, localSshPort, true); err != nil {
		return err
	}

	// 安装 tun 设备
	if opt.Get().Connect.DisableTunDevice {
		if util.IsWindows() {
			log.Warn().Msgf("DNS mode will switch to 'hosts' when tun device is disabled")
			opt.Get().Connect.DnsMode = util.DnsModeHosts
		}
		showSetupSocksMessage(opt.Get().Connect.ProxyPort)
	} else {
		if err = tun.Ins().CheckContext(); err != nil {
			return err
		}
		// socks5代理暴露出来给tun设备使用
		socksAddr := fmt.Sprintf("socks5://127.0.0.1:%d", opt.Get().Connect.ProxyPort)
		if err = tun.Ins().ToSocks(socksAddr); err != nil {
			return err
		}
		log.Info().Msgf("Tun device %s is ready", tun.Ins().GetName())
		// 配置系统路由表
		if !opt.Get().Connect.DisableTunRoute {
			if err = setupTunRoute(); err != nil {
				return err
			}
			log.Info().Msgf("Route to tun device completed")
		}
	}
	// 配置dns
	return setupDns(podName, podIP)
}

func setupTunRoute() error {
	// 根据 k8s 集群的 svc 和 pod 生成 cidr
	cidr, excludeCidr := cluster.Ins().ClusterCidr(opt.Get().Global.Namespace)
	/*
		根据cidr设置 tun 设备的规则
		比如cidr有存在一项 192.168.1.0/24, tun设备为 utun2, 则会生成如下规则
		ifconfig utun2 inet 192.168.1.0/24 192.168.1.0 或者 ifconfig utun2 add 192.168.1.0/24 192.168.1.0
		route add -net 192.168.1.0/24 -interface utun2
	*/
	err := tun.Ins().SetRoute(cidr, excludeCidr)
	if err != nil {
		if tun.IsAllRouteFailError(err) {
			if strings.Contains(err.(tun.AllRouteFailError).OriginalError().Error(), "exit status") {
				log.Warn().Msgf(err.Error())
			} else {
				log.Warn().Err(err.(tun.AllRouteFailError).OriginalError()).Msgf(err.Error())
			}
			return err
		}
		if strings.Contains(err.Error(), "exit status") {
			log.Warn().Msgf("Some route rule is not setup properly")
		} else {
			log.Warn().Err(err).Msgf("Some route rule is not setup properly")
		}
	}
	if failedRoutes := tun.Ins().CheckRoute(cidr); len(failedRoutes) > 0 {
		log.Warn().Msgf("Skipped route to %v", failedRoutes)
	}
	return nil
}

func startSocks5Connection(podIP, privateKey string, localSshPort int, isInitConnect bool) error {
	var res = make(chan error)
	var ticker *time.Ticker
	sshAddress := fmt.Sprintf("127.0.0.1:%d", localSshPort)
	socks5Address := fmt.Sprintf("127.0.0.1:%d", opt.Get().Connect.ProxyPort)
	gone := false
	go func() {
		// will hang here if not error happen
		err := sshchannel.Ins().StartSocks5Proxy(privateKey, sshAddress, socks5Address)
		if !gone {
			res <- err
		}
		log.Debug().Err(err).Msgf("Socks proxy interrupted")
		if ticker != nil {
			ticker.Stop()
		}
		time.Sleep(10 * time.Second)
		log.Debug().Msgf("Socks proxy reconnecting ...")
		_ = startSocks5Connection(podIP, privateKey, localSshPort, false)
	}()
	select {
	case err := <-res:
		if isInitConnect {
			log.Warn().Err(err).Msgf("Failed to setup socks proxy connection")
		}
		return err
	case <-time.After(1 * time.Second):
		ticker = setupSocks5HeartBeat(podIP, socks5Address)
		log.Info().Msgf("Socks proxy established")
		gone = true
		return nil
	}
}

func setupSocks5HeartBeat(podIP, socks5Address string) *time.Ticker {
	dialer, err := proxy.SOCKS5("tcp", socks5Address, nil, proxy.Direct)
	if err != nil {
		log.Warn().Err(err).Msgf("Failed to create socks proxy heart beat ticker")
	}
	ticker := time.NewTicker(60 * time.Second)
	go func() {
	TickLoop:
		for {
			select {
			case <-ticker.C:
				if c, err2 := dialer.Dial("tcp", fmt.Sprintf("%s:%d", podIP, common.StandardSshPort)); err2 != nil {
					log.Debug().Err(err2).Msgf("Socks proxy heartbeat interrupted")
				} else {
					_ = c.Close()
					log.Debug().Msgf("Heartbeat socks proxy ticked at %s", util.FormattedTime())
				}
			case <-time.After(2 * 60 * time.Second):
				log.Debug().Msgf("Socks proxy heartbeat stopped")
				break TickLoop
			}
		}
	}()
	return ticker
}

func showSetupSocksMessage(socksPort int) {
	if util.IsWindows() {
		if util.IsCmd() {
			log.Info().Msgf(">> Please setup proxy config by: set http_proxy=socks5://127.0.0.1:%d <<", socksPort)
		} else {
			log.Info().Msgf(">> Please setup proxy config by: $env:http_proxy=\"socks5://127.0.0.1:%d\" <<", socksPort)
		}
	} else {
		log.Info().Msgf(">> Please setup proxy config by: export http_proxy=socks5://127.0.0.1:%d <<", socksPort)
	}
}
