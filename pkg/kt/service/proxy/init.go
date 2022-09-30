package proxy

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

var (
	SshConfigList []*SshConfig
	SshConfigMap  = map[string]*SshConfig{}
)

func InitSshConfig(sshConfigFile string) ([]*SshConfig, error) {
	buff, err := ioutil.ReadFile(sshConfigFile)
	if err != nil {
		return nil, err
	}
	if err = yaml.Unmarshal(buff, &SshConfigList); err != nil {
		return nil, err
	}
	for _, cfg := range SshConfigList {
		SshConfigMap[cfg.Name] = cfg
	}
	return SshConfigList, nil
}

func FindSshConfig(remoteIp string) *SshConfig {
	var targetSshConfig *SshConfig
	for _, cfg := range SshConfigList {
		if cfg.Name == remoteIp {
			targetSshConfig = cfg
			break
		}
	}
	return targetSshConfig
}
