package cluster

import (
	"fmt"
	opt "github.com/alibaba/kt-connect/pkg/kt/command/options"
	"github.com/alibaba/kt-connect/pkg/kt/util"
	"github.com/rs/zerolog/log"
	"net"
	"strconv"
	"strings"
	"time"
)

// LastHeartBeatStatus record last heart beat status to avoid verbose log
var LastHeartBeatStatus = make(map[string]bool)

// SetupTimeDifference get time difference between cluster and local
func SetupTimeDifference() error {
	rectifierPodName := fmt.Sprintf("%s%s", util.RectifierPodPrefix, strings.ToLower(util.RandomString(5)))
	_, err := Ins().CreateRectifierPod(rectifierPodName)
	if err != nil {
		return err
	}
	stdout, stderr, err := Ins().ExecInPod(util.DefaultContainer, rectifierPodName, opt.Get().Global.Namespace, "date", "+%s")
	if err != nil {
		return err
	}
	go func() {
		if err2 := Ins().RemovePod(rectifierPodName, opt.Get().Global.Namespace); err2 != nil {
			log.Debug().Err(err).Msgf("Failed to remove pod %s", rectifierPodName)
		}
	}()
	remoteTime, err := strconv.ParseInt(stdout, 10, 0)
	if err != nil {
		log.Warn().Msgf("Invalid cluster time: '%s' %s", stdout, stderr)
		return err
	}
	timeDifference := remoteTime - time.Now().Unix()
	if timeDifference >= -1 && timeDifference <= 1 {
		log.Debug().Msgf("No time difference")
	} else {
		log.Debug().Msgf("Time difference is %d", timeDifference)
	}
	util.TimeDifference = timeDifference
	return nil
}

// SetupHeartBeat setup heartbeat watcher
func SetupHeartBeat(name, namespace string, updater func(string, string)) {
	// 启动定时器，定期执行更新函数
	ticker := time.NewTicker(time.Minute*util.ResourceHeartBeatIntervalMinus - util.RandomSeconds(0, 10))
	go func() {
		for range ticker.C {
			updater(name, namespace)
		}
	}()
}

// SetupPortForwardHeartBeat setup heartbeat watcher for port forward
func SetupPortForwardHeartBeat(port int) *time.Ticker {
	// 启动定时器，定期轮训port是否存活
	ticker := time.NewTicker(util.PortForwardHeartBeatIntervalSec*time.Second - util.RandomSeconds(0, 5))
	go func() {
	TickLoop:
		for {
			select {
			case <-ticker.C:
				// 检测方法，dial一次然后close掉，执行没有超时即可
				if conn, err := net.Dial("tcp", fmt.Sprintf(":%d", port)); err != nil {
					log.Warn().Err(err).Msgf("Heartbeat port forward %d ticked failed", port)
				} else {
					log.Debug().Msgf("Heartbeat port forward %d ticked at %s", port, util.FormattedTime())
					_ = conn.Close()
				}
			case <-time.After(2 * util.PortForwardHeartBeatIntervalSec * time.Second):
				// 如果ticker定时器执行超时了，达到2 * timeout则触发此case分支，跳出循环，完成goroutine的资源回收
				log.Debug().Msgf("Port forward heartbeat %d stopped", port)
				break TickLoop
			}
		}
	}()
	return ticker
}

func resourceHeartbeatPatch() string {
	return fmt.Sprintf("[ { \"op\" : \"replace\" , \"path\" : \"/metadata/annotations/%s\" , \"value\" : \"%s\" } ]",
		util.KtLastHeartBeat, util.GetTimestamp())
}
