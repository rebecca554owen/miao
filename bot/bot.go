package bot

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
	tele "gopkg.in/telebot.v4"

	"miao/bot/handler"
	"miao/bot/middleware"
	"miao/config"
)

// Bot 结构体，包含机器人实例
type Bot struct {
	teleBot *tele.Bot
}

// NewBot 创建新的机器人实例
func NewBot(cfg *config.Config) (*Bot, error) {
	// 初始化机器人设置
	pref := tele.Settings{
		Token:     cfg.Bot.Token,
		Poller:    &tele.LongPoller{Timeout: 10 * time.Second},
		ParseMode: cfg.Bot.ParseMode,
		OnError: func(err error, c tele.Context) {
			log.Printf("Telegram bot error: %v", err)
		},
	}

	// 如果配置了IPv6
	if cfg.Bot.IPv6 {
		pref.Client = &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Resolver: &net.Resolver{
						PreferGo: true,
						Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
							return net.Dial("udp6", "[2001:4860:4860::8888]:53")
						},
					},
				}).DialContext,
			},
		}
	}

	// 创建机器人实例
	teleBot, err := tele.NewBot(pref)
	if err != nil {
		return nil, fmt.Errorf("failed to create bot: %v", err)
	}

	// 创建机器人结构体
	b := &Bot{
		teleBot: teleBot,
	}

	// 添加中间件记录日志
	b.teleBot.Use(middleware.Logging())

	// 如果启用严格模式
	if cfg.Bot.StrictMode {
		b.teleBot.Use(func(next tele.HandlerFunc) tele.HandlerFunc {
			return func(c tele.Context) error {
				// 检查用户是否在允许列表中
				for _, adminID := range cfg.Admin {
					if c.Sender().ID == int64(adminID) {
						return next(c)
					}
				}
				return c.Send("抱歉，您没有权限使用此机器人")
			}
		})
	}

	// 创建处理器
	handler := handler.NewHandler(teleBot)
	// 并注册命令
	handler.RegisterCommand()

	return b, nil
}

// Start 启动机器人
func (b *Bot) Start() {
	log.Printf("机器人已启动，用户名 @%s ", b.teleBot.Me.Username)
	b.teleBot.Start()
}

// Stop 停止机器人
func (b *Bot) Stop() error {
	if b.teleBot != nil {
		log.Println("收到终止信号，正在关闭机器人...")
		b.teleBot.Stop()
		log.Println("机器人已成功关闭。")
		return nil
	}
	return nil
}