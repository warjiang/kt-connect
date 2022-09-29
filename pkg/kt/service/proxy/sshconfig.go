package proxy

import (
	"errors"
	"fmt"
	"github.com/wzshiming/sshproxy"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
)

// AuthType ssh类型
type AuthType string

const (
	AuthByPrivateKey AuthType = "privateKey"
	AuthByPassword   AuthType = "password"
)

type SshConfig struct {
	Name       string   `yaml:"name"`
	Host       string   `yaml:"host"`
	Port       string   `yaml:"port"`
	User       string   `yaml:"user"`
	AuthType   AuthType `yaml:"authType"`
	PrivateKey string   `yaml:"privateKey"`
	Password   string   `yaml:"password"`
	Tags       []string `yaml:"tags"`
	Dependency string   `yaml:"dependency"`
}

func (config *SshConfig) Check() error {
	if config.Name == "" {
		return errors.New("empty ssh name")
	}
	if config.Host == "" {
		return errors.New("empty ssh host")
	}
	if config.Port == "" {
		return errors.New("empty ssh port")
	}
	if config.User == "" {
		return errors.New("empty ssh user")
	}
	if config.Password == "" && config.PrivateKey == "" {
		return errors.New("private key or password cannot empty at same time")
	}
	return nil
}

func (config *SshConfig) BuildSshProxy(sshConfigMap map[string]*SshConfig) (
	*sshproxy.Dialer, error) {
	sshConfigList := make([]*SshConfig, 0, 2)
	current := config
	for {
		sshConfigList = append(sshConfigList, current)
		tmp, exist := sshConfigMap[current.Dependency]
		if exist {
			current = tmp
		} else {
			if current.Dependency != "" {
				return nil, errors.New(fmt.Sprintf("dependency:%s for %s not exist",
					current.Dependency, current.Name))
			}
			break
		}
	}
	var last *sshproxy.Dialer = nil
	for i := len(sshConfigList) - 1; i >= 0; i -= 1 {
		sshCfg := sshConfigList[i]
		var config *ssh.ClientConfig
		if sshCfg.AuthType == AuthByPrivateKey {
			buff, err1 := ioutil.ReadFile(sshCfg.PrivateKey)
			key, err2 := ssh.ParsePrivateKey(buff)
			if err1 != nil || err2 != nil {
				return nil, errors.New("get private key failed")
			}
			config = &ssh.ClientConfig{
				User:            sshCfg.User,
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Auth: []ssh.AuthMethod{
					ssh.PublicKeys(key),
				},
			}
		} else if sshCfg.AuthType == AuthByPassword {
			config = &ssh.ClientConfig{
				User:            sshCfg.User,
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Auth: []ssh.AuthMethod{
					ssh.Password(sshCfg.Password),
				},
			}
		} else {
			return nil, errors.New(fmt.Sprintf("unspported auth type: %s", sshCfg.AuthType))
		}
		host := fmt.Sprintf("%s:%s", sshCfg.Host,
			sshCfg.Port)
		dialer, err := sshproxy.NewDialerWithConfig(host, config)
		if err != nil {
			return nil, err
		}
		if last != nil {
			dialer.ProxyDial = last.DialContext
		}
		last = dialer
	}
	return last, nil
}
