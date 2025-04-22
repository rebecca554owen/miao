package config

import (
	"fmt"
	"github.com/spf13/viper"
)

// Config 结构体，用于存储配置信息
type Config struct {
    Admin []int64 `yaml:"admin"` // 管理员ID列表
    Bot struct {
        Token  string  `yaml:"token"`
    } `yaml:"bot"`

    SlaveConfig struct {
        HealthCheck struct {
            NumSamples     int    `yaml:"numSamples"`
            ShowStatusStyle string `yaml:"showStatusStyle"`
        } `yaml:"healthCheck"`
        Slaves []struct {
            Type          string `yaml:"type"`
            ID            string `yaml:"id"`
            Token         string `yaml:"token"`
            Address       string `yaml:"address"`
            Path          string `yaml:"path"`
            Invoker       string `yaml:"invoker"`
            BuildToken    string `yaml:"buildtoken"`
            Comment       string `yaml:"comment"`
            Option struct {
                DownloadDuration  int      `yaml:"downloadDuration"`
                DownloadThreading int      `yaml:"downloadThreading"`
                DownloadURL      string   `yaml:"downloadURL"`
                PingAddress      string   `yaml:"pingAddress"`
                PingAverageOver  int      `yaml:"pingAverageOver"`
                StunURL         string   `yaml:"stunURL"`
                TaskRetry       int      `yaml:"taskRetry"`
                TaskTimeout     int      `yaml:"taskTimeout"`
                DNSServer      []string `yaml:"dnsServer"`
                APIVersion     int      `yaml:"apiVersion"`
            } `yaml:"option"`
        } `yaml:"slaves"`
    } `yaml:"slaveConfig"`

    User []int64 `yaml:"user"` // 用户权限名单
}

// Load 使用 viper 读取并解析 config.yaml 文件
func Load(path string) (*Config, error) {
    // 初始化 viper
    v := viper.New()
    v.SetConfigFile(path)
    v.SetConfigType("yaml")

    // 读取配置文件
    if err := v.ReadInConfig(); err != nil {
        return nil, fmt.Errorf("读取配置文件失败: %v", err)
    }

    // 解析配置到结构体
    var cfg Config
    if err := v.Unmarshal(&cfg); err != nil {
        return nil, fmt.Errorf("解析配置失败: %v", err)
    }

    return &cfg, nil
}
