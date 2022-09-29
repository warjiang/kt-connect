package connect

import (
	"fmt"
	"github.com/alibaba/kt-connect/pkg/common"
	opt "github.com/alibaba/kt-connect/pkg/kt/command/options"
	"github.com/alibaba/kt-connect/pkg/kt/service/cluster"
	"github.com/alibaba/kt-connect/pkg/kt/service/dns"
	"github.com/alibaba/kt-connect/pkg/kt/transmission"
	"github.com/alibaba/kt-connect/pkg/kt/util"
	"github.com/rs/zerolog/log"
	coreV1 "k8s.io/api/core/v1"
	"strings"
	"time"
)

func setupDns(shadowPodName, shadowPodIp string) error {
	if strings.HasPrefix(opt.Get().Connect.DnsMode, util.DnsModeHosts) {
		log.Info().Msgf("Setting up dns in hosts mode")
		dump2HostsNamespaces := ""
		pos := len(util.DnsModeHosts)
		if len(opt.Get().Connect.DnsMode) > pos+1 && opt.Get().Connect.DnsMode[pos:pos+1] == ":" {
			dump2HostsNamespaces = opt.Get().Connect.DnsMode[pos+1:]
		}
		if err := dumpToHost(dump2HostsNamespaces); err != nil {
			return err
		}
	} else if opt.Get().Connect.DnsMode == util.DnsModePodDns {
		log.Info().Msgf("Setting up dns in pod mode")
		return dns.SetNameServer(shadowPodIp)
	} else if strings.HasPrefix(opt.Get().Connect.DnsMode, util.DnsModeLocalDns) {
		// localDNS 模式
		log.Info().Msgf("Setting up dns in local mode")
		// 获取 namespace 下面 svc 到 pod ip 之间的映射关系 & headless 服务的 pod 列表
		svcToIp, headlessPods := getServiceHosts(opt.Get().Global.Namespace, true)
		// svc name 到 pod ip 的映射关系写入到 hosts 文件中
		if err := dns.DumpHosts(svcToIp, ""); err != nil {
			return err
		}
		// 监听服务的变化, 变更之后会自动重新写入到 hosts 文件中
		watchServicesAndPods(opt.Get().Global.Namespace, svcToIp, headlessPods, true)

		// 生成随机tcp端口号
		forwardedPodPort := util.GetRandomTcpPort()
		if _, err := transmission.SetupPortForwardToLocal(shadowPodName, common.StandardDnsPort, forwardedPodPort); err != nil {
			return err
		}

		dnsPort := util.AlternativeDnsPort
		if util.IsWindows() {
			dnsPort = common.StandardDnsPort
		} else if util.IsMacos() {
			dnsPort = opt.Get().Connect.DnsPort
		}
		// must set up name server before change dns config
		// otherwise the upstream name server address will be incorrect in linux
		if err := dns.SetupLocalDns(forwardedPodPort, dnsPort, getDnsOrder(opt.Get().Connect.DnsMode)); err != nil {
			log.Error().Err(err).Msgf("Failed to setup local dns server")
			return err
		}
		return dns.SetNameServer(fmt.Sprintf("%s:%d", common.Localhost, dnsPort))
	} else {
		return fmt.Errorf("invalid dns mode: '%s', supportted mode are %s, %s, %s", opt.Get().Connect.DnsMode,
			util.DnsModeLocalDns, util.DnsModePodDns, util.DnsModeHosts)
	}
	return nil
}

func getDnsOrder(dnsMode string) []string {
	if !strings.Contains(dnsMode, ":") {
		return []string{util.DnsOrderCluster, util.DnsOrderUpstream}
	}
	return strings.Split(strings.SplitN(dnsMode, ":", 2)[1], ",")
}

func watchServicesAndPods(namespace string, svcToIp map[string]string, headlessPods []string, shortDomainOnly bool) {
	setupTime := time.Now().Unix()
	go cluster.Ins().WatchService("", namespace,
		func(svc *coreV1.Service) {
			// ignore add service event during watch setup
			if time.Now().Unix()-setupTime > 3 {
				svcToIp, headlessPods = getServiceHosts(namespace, shortDomainOnly)
				_ = dns.DumpHosts(svcToIp, namespace)
			}
		},
		func(svc *coreV1.Service) {
			svcToIp, headlessPods = getServiceHosts(namespace, shortDomainOnly)
			_ = dns.DumpHosts(svcToIp, namespace)
		}, nil)
	go cluster.Ins().WatchPod("", namespace, nil, func(pod *coreV1.Pod) {
		if util.Contains(headlessPods, pod.Name) {
			// it may take some time for new pod get assign an ip
			time.Sleep(5 * time.Second)
			svcToIp, headlessPods = getServiceHosts(namespace, shortDomainOnly)
			_ = dns.DumpHosts(svcToIp, namespace)
		}
	}, nil)
}

func dumpToHost(targetNamespaces string) error {
	namespacesToDump := []string{opt.Get().Global.Namespace}
	if targetNamespaces != "" {
		namespacesToDump = []string{}
		for _, ns := range strings.Split(targetNamespaces, ",") {
			namespacesToDump = append(namespacesToDump, ns)
		}
	}
	hosts := map[string]string{}
	for _, namespace := range namespacesToDump {
		log.Debug().Msgf("Search service in %s namespace ...", namespace)
		svcToIp, headlessPods := getServiceHosts(namespace, false)
		watchServicesAndPods(namespace, svcToIp, headlessPods, false)
		for svc, ip := range svcToIp {
			hosts[svc] = ip
		}
	}
	return dns.DumpHosts(hosts, "")
}

func getServiceHosts(namespace string, shortDomainOnly bool) (map[string]string, []string) {
	hosts := make(map[string]string)
	podNames := make([]string, 0)
	// 获取指定namespace下面的所有服务
	services, err := cluster.Ins().GetAllServiceInNamespace(namespace)
	if err == nil {
		for _, service := range services.Items {
			ip := service.Spec.ClusterIP
			if ip == "" || ip == "None" {
				// 处理 headless 服务
				// 根据 label 过滤去对应的 pod 列表
				pods, err2 := cluster.Ins().GetPodsByLabel(service.Spec.Selector, namespace)
				if err2 != nil || len(pods.Items) == 0 {
					continue
				}
				// 遍历所有 pod 列表, 遍历出分配了 ip 的 pod, 记录到 podNames 数组中
				for _, p := range pods.Items {
					ip = p.Status.PodIP
					if ip != "" {
						podNames = append(podNames, p.Name)
						break
					}
				}
				log.Debug().Msgf("Headless service found: %s.%s %s", service.Name, namespace, ip)
			} else {
				// 处理普通服务
				log.Debug().Msgf("Service found: %s.%s %s", service.Name, namespace, ip)
			}
			if shortDomainOnly {
				// 开启 shortDomainOnly 的情况下， 维护 svc name 到 pod ip的映射关系
				hosts[service.Name] = ip
			} else {
				// 除了维护当前namespace下 svc name 到 pod ip之间的映射关系之外
				if namespace == opt.Get().Global.Namespace {
					hosts[service.Name] = ip
				}
				// 还维护了 svcname.namespace 到 pod ip之间的映射
				hosts[fmt.Sprintf("%s.%s", service.Name, namespace)] = ip
				// 以及fqdn形式即 svcname.namespace.svc.domain 到 pod ip 之间的映射关系
				hosts[fmt.Sprintf("%s.%s.svc.%s", service.Name, namespace, opt.Get().Connect.ClusterDomain)] = ip
			}
		}
	}
	return hosts, podNames
}

func getOrCreateShadow() (string, string, string, error) {
	// 1. 生成shadow容器名, {kt-connect-shadow-[长度为5的随机容器名]}
	shadowPodName := fmt.Sprintf("kt-connect-shadow-%s", strings.ToLower(util.RandomString(5)))
	// 2. 开启shadow容器共享模式则使用默认shadow容器名
	if opt.Get().Connect.ShareShadow {
		shadowPodName = fmt.Sprintf("kt-connect-shadow-daemon")
	}

	endPointIP, podName, privateKeyPath, err := cluster.Ins().GetOrCreateShadow(shadowPodName, getLabels(),
		make(map[string]string), getEnvs(), "", map[int]string{})
	if err != nil {
		return "", "", "", err
	}

	return endPointIP, podName, privateKeyPath, nil
}

func getEnvs() map[string]string {
	envs := make(map[string]string)
	localDomains := dns.GetLocalDomains()
	if localDomains != "" {
		log.Debug().Msgf("Found local domains: %s", localDomains)
		envs[common.EnvVarLocalDomains] = localDomains
	}
	if strings.HasPrefix(opt.Get().Connect.DnsMode, util.DnsModeLocalDns) {
		envs[common.EnvVarDnsProtocol] = "tcp"
	} else {
		envs[common.EnvVarDnsProtocol] = "udp"
	}
	if opt.Get().Global.Debug {
		envs[common.EnvVarLogLevel] = "debug"
	} else {
		envs[common.EnvVarLogLevel] = "info"
	}
	return envs
}

func getLabels() map[string]string {
	labels := map[string]string{
		util.KtRole: util.RoleConnectShadow,
	}
	if opt.Get().Global.UseShadowDeployment {
		labels[util.KtTarget] = util.RandomString(20)
	}
	return labels
}
