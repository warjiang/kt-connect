package cluster

import (
	"context"
	"fmt"
	opt "github.com/alibaba/kt-connect/pkg/kt/command/options"
	"github.com/alibaba/kt-connect/pkg/kt/util"
	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strconv"
	"strings"
)

// ClusterCidr get cluster CIDR
func (k *Kubernetes) ClusterCidr(namespace string) ([]string, []string) {
	// 获取svc ip列表并构造svcCidr
	ips := getServiceIps(k.Clientset, namespace)
	log.Debug().Msgf("Found %d IPs", len(ips))
	svcCidr := calculateMinimalIpRange(ips)
	log.Debug().Msgf("Service CIDR are: %v", svcCidr)

	// 获取pod ip列表并构造podCidr
	var podCidr []string
	if !opt.Get().Connect.DisablePodIp {
		ips = getPodIps(k.Clientset, namespace)
		log.Debug().Msgf("Found %d IPs", len(ips))
		podCidr = calculateMinimalIpRange(ips)
		log.Debug().Msgf("Pod CIDR are: %v", podCidr)
	}

	apiServerIp := util.ExtractHostIp(opt.Store.RestConfig.Host)
	log.Debug().Msgf("Using cluster IP %s", apiServerIp)

	// 合并生成svc、pod的cidr
	cidr := mergeIpRange(svcCidr, podCidr, apiServerIp)
	log.Debug().Msgf("Cluster CIDR are: %v", cidr)

	// --exclude-ips 也需要包含 apiServerIp/32
	excludeIps := strings.Split(opt.Get().Connect.ExcludeIps, ",")
	var excludeCidr []string
	if len(apiServerIp) > 0 {
		excludeIps = append(excludeIps, apiServerIp+"/32")
	}

	// --include-ips 需要包含到代理的 cidr 中
	if opt.Get().Connect.IncludeIps != "" {
		for _, ipRange := range strings.Split(opt.Get().Connect.IncludeIps, ",") {
			if opt.Get().Connect.Mode == util.ConnectModeTun2Socks && isSingleIp(ipRange) {
				log.Warn().Msgf("Includes single IP '%s' is not allow in %s mode", ipRange, util.ConnectModeTun2Socks)
			} else {
				cidr = append(cidr, ipRange)
			}
		}
	}
	// --exclude-ips 到这里包含了[用户手动指定的ip]
	if opt.Get().Connect.ExcludeIps != "" {
		for _, ipRange := range excludeIps {
			var toRemove []string
			for _, r := range cidr {
				if r == ipRange {
					// cidr 中如果包含了 excludeIp, 记录到 toRemove 数组中
					toRemove = append(toRemove, r)
					break
				} else if isPartOfRange(ipRange, r) {
					// excludeIp 包含了 cidr, 记录到 toRemove 数组中
					toRemove = append(toRemove, r)
				} else if isPartOfRange(r, ipRange) {
					// exclude-ips 和 cidr 产生overlap情况, 通过excludeCidr数组记录下
					excludeCidr = append(excludeCidr, ipRange)
					break
				}
				// 这里剩余的  exclude-ips 不属于 cidr 直接忽略
			}
			for _, r := range toRemove {
				cidr = util.ArrayDelete(cidr, r)
			}
		}
	}
	if len(excludeCidr) > 0 {
		log.Debug().Msgf("Non-cluster CIDR are: %v", excludeCidr)
	}
	return cidr, excludeCidr
}

func mergeIpRange(svcCidr []string, podCidr []string, apiServerIp string) []string {
	// 合并 svcCidr 和 podCidr
	cidr := calculateMinimalIpRange(append(svcCidr, podCidr...))
	apiServerOverlap := false
	for _, r := range cidr {
		// 计算cidr的目的算出一个最大的cidr值，对cidr包含的ip进行代理
		// 精确命中 apiServerIp/32 如果能够包含 apiServerIp 则需要将apiServerIp从中移除
		if isPartOfRange(r, apiServerIp+"/32") {
			apiServerOverlap = true
			break
		}
	}
	if !apiServerOverlap {
		return cidr
	}

	// A workaround of issue-320
	// 分别从 svcCidr 和 podCidr 中移除 apiServerIp, 避免apiSever被代理
	return append(removeCidrOf(svcCidr, apiServerIp), removeCidrOf(podCidr, apiServerIp)...)
}

func removeCidrOf(cidrRanges []string, ipRange string) []string {
	var newRange []string
	for _, cidr := range cidrRanges {
		if !isPartOfRange(cidr, ipRange) {
			newRange = append(newRange, cidr)
		}
	}
	return newRange
}

// 判断 subIpRange 是否为 ipRange的子网
func isPartOfRange(ipRange string, subIpRange string) bool {
	// ipRange 和 subIpRange 均从 cidr 模式转换成 ipBin 的模式，即二进制数组
	ipRangeBin, err := ipRangeToBin(ipRange)
	if err != nil {
		return false
	}
	subIpRangeBin, err := ipRangeToBin(subIpRange)
	if err != nil {
		return false
	}
	for i := 0; i < 32; i++ {
		if ipRangeBin[i] == -1 {
			// ipRangeBin[i] == -1
			// 此时无论subIpRangeBin[i] 为-1 还是 0都可以表示 subIpRange是 ipRange 的子网
			return true
		}
		// 第一次出现不一致, 肯定不是子网
		if subIpRangeBin[i] != ipRangeBin[i] {
			return false
		}
	}
	// 全匹配了返回true
	return true
}

func getPodIps(k kubernetes.Interface, namespace string) []string {
	podList, err := k.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		Limit:          1000,
		TimeoutSeconds: &apiTimeout,
	})
	if err != nil {
		podList, err = k.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
			Limit:          1000,
			TimeoutSeconds: &apiTimeout,
		})
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to fetch pod ips")
			return []string{}
		}
	}

	var ips []string
	for _, pod := range podList.Items {
		if pod.Status.PodIP != "" && pod.Status.PodIP != "None" {
			ips = append(ips, pod.Status.PodIP)
		}
	}

	return ips
}

func getServiceIps(k kubernetes.Interface, namespace string) []string {
	// 尝试获取默认namespace下的服务列表
	serviceList, err := k.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{
		Limit:          1000,
		TimeoutSeconds: &apiTimeout,
	})
	if err != nil {
		// 异常情况下尝试获取指定namespace下面的服务列表
		serviceList, err = k.CoreV1().Services(namespace).List(context.TODO(), metav1.ListOptions{
			Limit:          1000,
			TimeoutSeconds: &apiTimeout,
		})
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to fetch service ips")
			return []string{}
		}
	}
	// service列表 => 提取所有clusterIp不为空的ip列表
	var ips []string
	for _, service := range serviceList.Items {
		if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != "None" {
			ips = append(ips, service.Spec.ClusterIP)
		}
	}

	return ips
}

func calculateMinimalIpRange(ips []string) []string {
	// 根据服务的clusterIp列表计算cidr
	var miniBins [][32]int
	threshold := 16
	withAlign := true
	for _, ip := range ips {
		ipBin, err := ipToBin(ip)
		if err != nil {
			// skip invalid ip
			continue
		}
		if len(miniBins) == 0 {
			// 第一次必然走这个逻辑，这里的逻辑写的太别扭了
			miniBins = append(miniBins, ipBin)
			continue
		}
		match := false
		for i, bins := range miniBins {
			for j, b := range bins {
				if b != ipBin[j] {
					if j >= threshold {
						// 只要匹配的位数超过 threshold 就通过，在不一致的地方用-1进行标记
						match = true
						miniBins[i][j] = -1
					}
					break
				} else if j == 31 {
					// 全匹配
					match = true
				}
			}
			if match {
				break
			}
		}
		if !match {
			// no include in current range, append it
			miniBins = append(miniBins, ipBin)
		}
	}
	var miniRange []string
	for _, bins := range miniBins {
		miniRange = append(miniRange, binToIpRange(bins, withAlign))
	}
	/*
		执行到这里会得到一堆cidr的结果
		比如[10.10.0.0/16,10.10.10.0/24]
	*/

	return miniRange
}

// 转换成cidr形式, 用-1(<0)来标记ip range的结尾
func binToIpRange(bins [32]int, withAlign bool) string {
	// ip:二进制数组
	// withAlign: mask表示掩码的位数, 比如mask=23 如果withAlign=true, 则按照8的倍数向下对齐, 这里23会align成16
	ips := []string{"0", "0", "0", "0"}
	mask := 0
	end := false
	for i := 0; i < 4; i++ {
		segment := 0
		factor := 128
		for j := 0; j < 8; j++ {
			if bins[i*8+j] < 0 {
				end = true
				break
			}
			segment += bins[i*8+j] * factor
			factor /= 2
			mask++
		}
		if !withAlign || !end {
			ips[i] = strconv.Itoa(segment)
		}
		if end {
			if withAlign {
				mask = i * 8
			}
			break
		}
	}
	return fmt.Sprintf("%s/%d", strings.Join(ips, "."), mask)
}

// cidr 转换成二进制数组
func ipRangeToBin(ipRange string) ([32]int, error) {
	// ipRange比如 10.10.1.0/24
	// 则会转换成
	// step1: [0000,1010,0000,1010,0000,000 1,0000,0000]
	// step2: [0000,1010,0000,1010,0000,000-1,0000,0000]
	parts := strings.Split(ipRange, "/")
	if len(parts) != 2 {
		return [32]int{}, fmt.Errorf("invalid ip range format: %s", ipRange)
	}
	sepIndex, err := strconv.Atoi(parts[1])
	if err != nil {
		return [32]int{}, err
	}
	ipBin, err := ipToBin(parts[0])
	if err != nil {
		return [32]int{}, err
	}
	if sepIndex < 32 {
		// 标记-1
		// 比如127.0.0.1通过ipToBin转换出来的结果为
		// step1: [0111,1111,0000,0000,0000,0000, 0000,0001]
		// step2: [0111,1111,0000,0000,0000,0000,-1000,0001]
		ipBin[sepIndex] = -1
	}
	return ipBin, nil
}

// 将输入的ip转换成长度为32的二进制数组
func ipToBin(ip string) (ipBin [32]int, err error) {
	// 如果ip为简单的点分十进制的模式,则按照将10进制转2进制的模式,分成4段依次转换
	// 如果ip本神就是cidr的模式, 则调用 ipRangeToBin 做一次转换, 掩码对应的二进制位上标记为-1

	// 统计 / 数量， / 最多出现一次
	slashCount := strings.Count(ip, "/")
	if slashCount == 1 {
		return ipRangeToBin(ip)
	} else if slashCount > 1 {
		err = fmt.Errorf("invalid ip address: %s", ip)
		return
	}
	ipNum, err := parseIp(ip)
	if err != nil {
		return
	}
	/*
		i=0 ipBin[0,8)   <= bin[:]
		i=1 ipBin[8,16)  <= bin[:]
		i=2 ipBin[16,24) <= bin[:]
		i=3 ipBin[24,32) <= bin[:]
	*/
	for i, n := range ipNum {
		bin := decToBin(n)
		copy(ipBin[i*8:i*8+8], bin[:])
	}
	return
}

// parseIp 将点分十进制转换成int数组
func parseIp(ip string) (ipNum [4]int, err error) {
	for i, seg := range strings.Split(ip, ".") {
		ipNum[i], err = strconv.Atoi(seg)
		if err != nil {
			return
		}
	}
	return
}

// decToBin 十进制转二进制
func decToBin(n int) [8]int {
	// 假设输入n=127
	// 则此时bin =[1,1,1,1,1,1,1,0]
	var bin [8]int
	for i := 0; n > 0; n /= 2 {
		bin[i] = n % 2
		i++
	}
	// 通过i,j两个指针对bin执行逆置操作
	for i, j := 0, len(bin)-1; i < j; i, j = i+1, j-1 {
		bin[i], bin[j] = bin[j], bin[i]
	}
	return bin
}
