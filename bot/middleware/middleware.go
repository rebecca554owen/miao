package middleware

import (
	"log"

	tele "gopkg.in/telebot.v4"
)

// Logging 日志记录中间件
func Logging() tele.MiddlewareFunc {
	return func(next tele.HandlerFunc) tele.HandlerFunc {
		return func(c tele.Context) error {
			log.Printf("ID %d 用户名 @%s 发送消息: %s", 
				c.Sender().ID, 
				c.Sender().Username, 
				c.Text())
			return next(c)
		}
	}
}