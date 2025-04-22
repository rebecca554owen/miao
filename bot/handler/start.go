package handler

import tele "gopkg.in/telebot.v4"

// handleStart 处理 /start 命令
func (h *Handler) handleStart(c tele.Context) error {
	text := `欢迎使用 MiaoBot！
作者: 周宇航
请选择：`
	return c.Send(text)
}