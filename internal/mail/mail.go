// Package mail sends the transactional email the application depends on:
// invitation links and password resets.
//
// It exists because those two flows are not optional decoration. An invitation
// token that comes back in an HTTP response instead of an email lets any admin
// mint a working link for an address they do not control -- and a product with no
// password reset locks a user out permanently the first time they forget one.
package mail

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

// Message is one email.
type Message struct {
	To      string
	Subject string
	// Body is plain text. Deliberately not HTML: transactional mail that must be
	// read and acted on beats mail that must be rendered, and a plain-text body
	// cannot carry a tracking pixel or an injection.
	Body string
}

// Mailer sends email.
//
// It is an interface with one method so that the template ships something that
// works out of the box (LogMailer), you can plug in whatever your project really
// uses (SES, Postmark, Resend, a queue), and the tests can assert on what was
// sent without a network.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// ---------------------------------------------------------------- log

// LogMailer prints the email to the application log instead of sending it.
//
// This is what makes the template runnable with zero setup: `make up`, invite
// somebody, and the invitation link is right there in `docker compose logs app`.
//
// It is NOT a stub that swallows mail. It prints the entire body, link included,
// which is exactly why settings.validate REFUSES to start with it in production:
// invitation and password-reset links in your logs are credentials in your logs.
type LogMailer struct {
	log *slog.Logger
}

// NewLogMailer returns a Mailer that logs instead of sending.
func NewLogMailer(log *slog.Logger) *LogMailer {
	return &LogMailer{log: log}
}

// Send prints the message.
func (m *LogMailer) Send(_ context.Context, msg Message) error {
	// Deliberately loud and multi-line: you are meant to find this in the logs and
	// copy the link out of it.
	m.log.Info("EMAIL (not sent -- MAIL_BACKEND=log)",
		slog.String("to", msg.To),
		slog.String("subject", msg.Subject),
		slog.String("body", "\n"+msg.Body),
	)
	return nil
}

// ---------------------------------------------------------------- smtp

// SMTPMailer sends over SMTP.
//
// Deliberately minimal -- net/smtp, no dependency. Most projects will replace this
// with their provider's SDK, and the Mailer interface is the seam for doing so.
type SMTPMailer struct {
	addr string // host:port
	from string
	auth smtp.Auth
}

// NewSMTPMailer builds an SMTP-backed Mailer. Username may be empty for a relay
// that does not authenticate (a local MTA, or MailHog in development).
func NewSMTPMailer(host string, port int, username, password, from string) *SMTPMailer {
	var auth smtp.Auth
	if username != "" {
		// PlainAuth refuses to send credentials over an unencrypted connection
		// unless the host is localhost -- which is the behaviour you want, and is
		// why this is not a custom auth type.
		auth = smtp.PlainAuth("", username, password, host)
	}
	return &SMTPMailer{
		addr: fmt.Sprintf("%s:%d", host, port),
		from: from,
		auth: auth,
	}
}

// Send delivers the message over SMTP.
func (m *SMTPMailer) Send(_ context.Context, msg Message) error {
	// Reject a header injection before it becomes one. A newline in the subject or
	// the recipient lets an attacker append their own headers -- Bcc, say -- and
	// turn your password-reset endpoint into an open relay. The addresses here come
	// from user input (an invitation's email), so this is not theoretical.
	if strings.ContainsAny(msg.To, "\r\n") || strings.ContainsAny(msg.Subject, "\r\n") {
		return fmt.Errorf("mail: refusing to send: a newline in the recipient or subject is a header injection")
	}

	body := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		m.from, msg.To, msg.Subject, msg.Body,
	)

	if err := smtp.SendMail(m.addr, m.auth, m.from, []string{msg.To}, []byte(body)); err != nil {
		return fmt.Errorf("mail: send to %s: %w", msg.To, err)
	}
	return nil
}
