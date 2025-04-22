package handler

import (
	tele "gopkg.in/telebot.v4"
)

type Handler struct {
	bot *tele.Bot
}

func NewHandler(bot *tele.Bot) *Handler {
	return &Handler{bot: bot}
}

// RegisterCommand 注册命令处理器
func (h *Handler) RegisterCommand() {
	h.bot.Handle("/start", h.handleStart)
	// 可以在这里添加更多命令注册
}
