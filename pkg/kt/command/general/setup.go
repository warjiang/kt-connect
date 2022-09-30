package general

import (
	"fmt"
	opt "github.com/alibaba/kt-connect/pkg/kt/command/options"
	"github.com/alibaba/kt-connect/pkg/kt/service/cluster"
	"github.com/alibaba/kt-connect/pkg/kt/service/proxy"
	"github.com/alibaba/kt-connect/pkg/kt/service/sshchannel"
	"github.com/alibaba/kt-connect/pkg/kt/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/wzshiming/socks5"
	k8sRuntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/klog/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

// Prepare setup log level, time difference and kube config
func Prepare() error {
	// 配置 zero log
	SetupLogger()

	// 组装 k8s 配置, 内部会完成restConfig和clientSet对象的初始化
	if err := combineKubeOpts(); err != nil {
		return err
	}

	log.Info().Msgf("KtConnect %s start at %d (%s %s)",
		opt.Store.Version, os.Getpid(), runtime.GOOS, runtime.GOARCH)
	// 对时间
	if !opt.Get().Global.UseLocalTime {
		if err := cluster.SetupTimeDifference(); err != nil {
			return err
		}
	}
	return nil
}

func SetupLogger() {
	// --debug 模式下调整zerolog的日志等级为debug
	if opt.Get().Global.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	util.PrepareLogger(opt.Get().Global.Debug)
	k8sRuntime.ErrorHandlers = []func(error){
		func(err error) {
			_, _ = util.BackgroundLogger.Write([]byte(err.Error() + util.Eol))
		},
	}
	klog.SetOutput(util.BackgroundLogger)
	klog.LogToStderr(false)
}

// SetupProcess write pid file and set component type
func SetupProcess(componentName string) (chan os.Signal, error) {
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
	opt.Store.Component = componentName
	return ch, util.WritePidFile(componentName, ch)
}

// combineKubeOpts set default options of kubectl if not assign
func combineKubeOpts() (err error) {
	var config *clientcmdapi.Config
	if opt.Get().Global.Kubeconfig != "" {
		// 通过 KUBECONFIG 的环境变量和 client-go 进行交互
		// 设置完环境变量之后, client-go 内部初始化 rest.Config 时会读取 KUBECONFIG 环境变量
		_ = os.Setenv(util.EnvKubeConfig, opt.Get().Global.Kubeconfig)
		config, err = clientcmd.NewDefaultClientConfigLoadingRules().Load()
	} else if customize, exist := opt.GetCustomizeKubeConfig(); exist {
		// when has customized kubeconfig, use it
		config, err = clientcmd.Load([]byte(customize))
	} else {
		// otherwise, fellow default kubeconfig load rule
		config, err = clientcmd.NewDefaultClientConfigLoadingRules().Load()
	}
	if err != nil {
		return fmt.Errorf("failed to parse kubeconfig: %s", err)
	} else if config == nil {
		// should not happen, but issue-275 and issue-285 may cause by it
		return fmt.Errorf("failed to parse kubeconfig")
	}
	// kubeconfig 文件中可能会包含多个 context, 如果手动指定了context则从kubeconfig中过滤出来
	// 并设置到config.CurrentContext字段上
	if len(opt.Get().Global.Context) > 0 {
		found := false
		for name, _ := range config.Contexts {
			if name == opt.Get().Global.Context {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("context '%s' not exist, check your kubeconfig file please", opt.Get().Global.Context)
		}
		config.CurrentContext = opt.Get().Global.Context
	}
	// kubeconfig的一个context下面会包含多个namespace, 如果用户没有手动指定namespace
	// 则优先查看context上是否指定了namespace, 如果指定了则优先使用context指定的namespace
	// 如果没有指定则使用default的namespace
	if len(opt.Get().Global.Namespace) == 0 {
		ctx, exists := config.Contexts[config.CurrentContext]
		if exists && len(ctx.Namespace) > 0 {
			opt.Get().Global.Namespace = config.Contexts[config.CurrentContext].Namespace
		} else {
			opt.Get().Global.Namespace = util.DefaultNamespace
		}
	}
	kubeConfigGetter := func() clientcmd.KubeconfigGetter {
		return func() (*clientcmdapi.Config, error) {
			return config, nil
		}
	}
	// 生成restConfig
	restConfig, err := clientcmd.BuildConfigFromKubeconfigGetter("", kubeConfigGetter())
	if err != nil {
		return err
	}
	if tmpUrl, err := url.Parse(restConfig.Host); err == nil {
		remoteHost := tmpUrl.Host
		idx := strings.Index(remoteHost, ":")
		if idx != -1 {
			remoteHost = remoteHost[:idx]
		}
		sshConfig := proxy.FindSshConfig(remoteHost)
		if sshConfig != nil {
			dialer, err := sshConfig.BuildSshProxy(proxy.SshConfigMap)
			if err == nil {
				go func() {
					socks5Address := "127.0.0.1:32280"
					svc := &socks5.Server{
						Logger:    sshchannel.SocksLogger{},
						ProxyDial: dialer.DialContext,
					}
					err = svc.ListenAndServe("tcp", socks5Address)
					if err != nil {
						return
					}
				}()
				//socks5dialer, err := socks5.NewDialer("socks5://127.0.0.1:32280")
				//if err == nil {
				//	restConfig.Dial = socks5dialer.DialContext
				//}
				restConfig.Proxy = func(request *http.Request) (*url.URL, error) {
					return url.Parse("socks5://127.0.0.1:32280")
				}
			}
		}
	}

	// 生成clientSet对象
	clientSet, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return err
	}
	// clientSet、restConfig 回写到 global 对象上
	opt.Store.Clientset = clientSet
	opt.Store.RestConfig = restConfig

	clusterName := "none"
	for name, context := range config.Contexts {
		if name == config.CurrentContext {
			clusterName = context.Cluster
			break
		}
	}
	log.Info().Msgf("Using cluster context %s (%s)", config.CurrentContext, clusterName)

	return nil
}
