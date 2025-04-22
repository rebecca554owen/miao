package bot

import (
	"fmt"
	"log"
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
	// 检查 Bot Token 是否存在
	if cfg.Bot.Token == "" {
		return nil, fmt.Errorf("Bot Token 不能为空")
	}
	// 初始化机器人设置
	pref := tele.Settings{
		Token:     cfg.Bot.Token,
		Poller:    &tele.LongPoller{Timeout: 10 * time.Second},
		OnError: func(err error, c tele.Context) {
			log.Printf("机器人初始化错误: %v", err)
		},
	}

	// 创建机器人实例
	teleBot, err := tele.NewBot(pref)
	if err != nil {
		return nil, fmt.Errorf("创建机器人失败: %v", err)
	}

	// 创建机器人结构体
	b := &Bot{
		teleBot: teleBot,
	}

	// 添加中间件记录日志
	b.teleBot.Use(middleware.Logging())

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
		return nil
	}
	return nil
}