package helper

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"

	"github.com/group-project/authentication/internal/config"
)

type EmailSender interface {
	SendOTP(ctx context.Context, toEmail, toName, otp string) error
}

// SMTPEmailSender sends emails via standard SMTP.
type SMTPEmailSender struct {
	host     string
	port     string
	username string
	password string
	from     string
	fromName string
}

func NewSMTPEmailSender(cfg config.SMTPConfig) *SMTPEmailSender {
	return &SMTPEmailSender{
		host:     cfg.Host,
		port:     cfg.Port,
		username: cfg.Username,
		password: cfg.Password,
		from:     cfg.From,
		fromName: cfg.FromName,
	}
}

func (s *SMTPEmailSender) SendOTP(_ context.Context, toEmail, toName, otp string) error {
	addr := fmt.Sprintf("%s:%s", s.host, s.port)
	var auth smtp.Auth
	if s.username != "" && s.password != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}

	subject := "Your Verification Code"
	body := fmt.Sprintf("Hello %s,\r\n\r\nYour verification code is: %s\r\n\r\nThis code will expire in 10 minutes.\r\nIf you did not request this, please ignore this email.\r\n", toName, otp)

	msg := []byte(strings.Join([]string{
		fmt.Sprintf("From: %s <%s>", s.fromName, s.from),
		fmt.Sprintf("To: %s", toEmail),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=\"UTF-8\"",
		"",
		body,
	}, "\r\n"))

	return smtp.SendMail(addr, auth, s.from, []string{toEmail}, msg)
}

// ConsoleEmailSender logs OTPs to stdout/slog for development and testing.
type ConsoleEmailSender struct{}

func NewConsoleEmailSender() *ConsoleEmailSender {
	return &ConsoleEmailSender{}
}

func (c *ConsoleEmailSender) SendOTP(_ context.Context, toEmail, toName, otp string) error {
	slog.Info("📨 [DEV EMAIL SENDER] Verification OTP",
		"to_email", toEmail,
		"to_name", toName,
		"otp", otp,
	)
	return nil
}

// NewEmailSender initializes an appropriate EmailSender based on configuration.
func NewEmailSender(cfg config.SMTPConfig) EmailSender {
	if cfg.Host == "" || strings.EqualFold(cfg.Host, "mock") {
		slog.Info("SMTP not configured or set to mock. Using ConsoleEmailSender (OTPs will print to server logs).")
		return NewConsoleEmailSender()
	}
	return NewSMTPEmailSender(cfg)
}
