package config

import (
	"github.com/spf13/viper"
)

// Config 存储应用程序配置
type Config struct {
	License string `mapstructure:"license"`
	Admin   []int  `mapstructure:"admin"`
	
	Network struct {
		HttpProxy  string `mapstructure:"httpProxy"`
		Socks5Proxy string `mapstructure:"socks5Proxy"`
		UserAgent  string `mapstructure:"userAgent"`
	} `mapstructure:"network"`

	Bot struct {
		Token      string `mapstructure:"bot-token"`
		ApiID      string `mapstructure:"api-id"`
		ApiHash    string `mapstructure:"api-hash"`
		Proxy      string `mapstructure:"proxy"`
		IPv6       bool   `mapstructure:"ipv6"`
		AntiGroup  bool   `mapstructure:"antiGroup"`
		StrictMode bool   `mapstructure:"strictMode"`
		BypassMode bool   `mapstructure:"bypassMode"`
		ParseMode  string `mapstructure:"parseMode"`
		InviteGroup []int `mapstructure:"inviteGroup"`
		CacheTime  int    `mapstructure:"cacheTime"`
		EchoLimit  float64 `mapstructure:"echoLimit"`
		InviteBlacklistURL []string `mapstructure:"inviteBlacklistURL"`
		InviteBlacklistDomain []string `mapstructure:"inviteBlacklistDomain"`
		
		Commands []struct {
			Name          string `mapstructure:"name"`
			Title         string `mapstructure:"title"`
			Enable        bool   `mapstructure:"enable"`
			Rule          string `mapstructure:"rule"`
			Pin           bool   `mapstructure:"pin"`
			Text          string `mapstructure:"text"`
			AttachToInvite bool `mapstructure:"attachToInvite"`
		} `mapstructure:"commands"`
	} `mapstructure:"bot"`

	Image struct {
		SpeedFormat string `mapstructure:"speedFormat"`
		Compress    bool   `mapstructure:"compress"`
		Emoji struct {
			Enable bool   `mapstructure:"enable"`
			Source string `mapstructure:"source"`
		} `mapstructure:"emoji"`
		EndColorsSwitch bool   `mapstructure:"endColorsSwitch"`
		Font            string `mapstructure:"font"`
		SpeedEndColorSwitch bool `mapstructure:"speedEndColorSwitch"`
		Invert          bool   `mapstructure:"invert"`
		Save            bool   `mapstructure:"save"`
		PixelThreshold  string `mapstructure:"pixelThreshold"`
		Title           string `mapstructure:"title"`
		
		Watermark struct {
			Alpha      int     `mapstructure:"alpha"`
			Angle      float64 `mapstructure:"angle"`
			Enable     bool    `mapstructure:"enable"`
			RowSpacing int     `mapstructure:"row-spacing"`
			Shadow     bool    `mapstructure:"shadow"`
			Size       int     `mapstructure:"size"`
			StartY     int     `mapstructure:"start-y"`
			Text       string  `mapstructure:"text"`
			Trace      bool    `mapstructure:"trace"`
		} `mapstructure:"watermark"`
	} `mapstructure:"image"`

	Runtime struct {
		Entrance      bool     `mapstructure:"entrance"`
		Interval      int      `mapstructure:"interval"`
		Ipstack       bool     `mapstructure:"ipstack"`
		Localip       bool     `mapstructure:"localip"`
		Nospeed       bool     `mapstructure:"nospeed"`
		PingURL       string   `mapstructure:"pingURL"`
		SpeedFiles    []string `mapstructure:"speedFiles"`
		SpeedNodes    int      `mapstructure:"speedNodes"`
		SpeedThreads  int      `mapstructure:"speedThreads"`
		Output        string   `mapstructure:"output"`
		Realtime      bool     `mapstructure:"realtime"`
		DisableSubCvt bool     `mapstructure:"disableSubCvt"`
	} `mapstructure:"runtime"`

	ScriptConfig struct {
		Scripts []struct {
			Type    string `mapstructure:"type"`
			Name    string `mapstructure:"name"`
			Rank    int    `mapstructure:"rank"`
			Content string `mapstructure:"content"`
		} `mapstructure:"scripts"`
	} `mapstructure:"scriptConfig"`

	SlaveConfig struct {
		HealthCheck struct {
			NumSamples        int    `mapstructure:"numSamples"`
			ShowStatusStyle   string `mapstructure:"showStatusStyle"`
			AutoHideOnFailure bool   `mapstructure:"autoHideOnFailure"`
		} `mapstructure:"healthCheck"`
		ShowID bool `mapstructure:"showID"`
		Slaves []struct {
			Type           string `mapstructure:"type"`
			ID             string `mapstructure:"id"`
			Token          string `mapstructure:"token"`
			Address        string `mapstructure:"address"`
			Path           string `mapstructure:"path"`
			SkipCertVerify bool   `mapstructure:"skipCertVerify"`
			Tls            bool   `mapstructure:"tls"`
			Invoker        string `mapstructure:"invoker"`
			Buildtoken     string `mapstructure:"buildtoken"`
			Comment        string `mapstructure:"comment"`
			Hidden         bool   `mapstructure:"hidden"`
			Proxy          string `mapstructure:"proxy"`
			
			Option struct {
				DownloadDuration  int    `mapstructure:"downloadDuration"`
				DownloadThreading int    `mapstructure:"downloadThreading"`
				DownloadURL      string `mapstructure:"downloadURL"`
				PingAddress      string `mapstructure:"pingAddress"`
				PingAverageOver  int    `mapstructure:"pingAverageOver"`
				StunURL          string `mapstructure:"stunURL"`
				TaskRetry        int    `mapstructure:"taskRetry"`
				TaskTimeout      int    `mapstructure:"taskTimeout"`
				DnsServer        []string `mapstructure:"dnsServer"`
				ApiVersion       int    `mapstructure:"apiVersion"`
			} `mapstructure:"option"`
		} `mapstructure:"slaves"`
	} `mapstructure:"slaveConfig"`

	Rules []struct {
		Name    string      `mapstructure:"name"`
		URL     string      `mapstructure:"url"`
		Owner   int64       `mapstructure:"owner"`
		Slaveid string      `mapstructure:"slaveid"`
		Runtime interface{} `mapstructure:"runtime"`
		Script  []string    `mapstructure:"script"`
	} `mapstructure:"rules"`

	Subconverter struct {
		Address string `mapstructure:"address"`
		Enable  bool   `mapstructure:"enable"`
		Tls     bool   `mapstructure:"tls"`
	} `mapstructure:"subconverter"`

	Substore struct {
		Enable     bool   `mapstructure:"enable"`
		Backend    string `mapstructure:"backend"`
		Ua         string `mapstructure:"ua"`
		AutoDeploy bool   `mapstructure:"autoDeploy"`
		Path       string `mapstructure:"path"`
		JsRuntime  string `mapstructure:"jsRuntime"`
	} `mapstructure:"substore"`

	Translation struct {
		Lang      string `mapstructure:"lang"`
		Resources map[string]string `mapstructure:"resources"`
	} `mapstructure:"translation"`

	LogLevel string `mapstructure:"log-level"`
	User     []int  `mapstructure:"user"`
	DetectInvalidResults bool `mapstructure:"detectInvalidResults"`
}

// Load 使用 viper 读取并解析 config.yaml 文件
func Load(path string) (*Config, error) {
	// 初始化 viper
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.AutomaticEnv() // 允许使用环境变量覆盖配置

	// 读取配置文件
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	// 解析配置到结构体
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
