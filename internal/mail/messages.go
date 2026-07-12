package mail

import "fmt"

// The two emails this application sends. They live here, next to the Mailer, so
// that changing what a user reads does not mean touching the identity service.
//
// Both carry a CREDENTIAL in a URL. Two consequences worth being deliberate about:
//
//   - The token is in the link's query string, and query strings end up in browser
//     history, in Referer headers, and in proxy logs. That is a known and accepted
//     cost of every email-link flow in existence; the mitigations are a short TTL
//     and single use, which both of these have.
//   - Never log these bodies in production. That is exactly why LogMailer is
//     refused when APP_ENV=production: it would put working credentials in your
//     log aggregator.

// Invitation builds the "you have been invited" email.
func Invitation(baseURL, tenantName, inviterEmail, token string) Message {
	link := fmt.Sprintf("%s/invitations/accept?token=%s", baseURL, token)

	return Message{
		Subject: fmt.Sprintf("You have been invited to join %s", tenantName),
		Body: fmt.Sprintf(`%s has invited you to join %s.

Accept the invitation:

    %s

If you do not have an account yet, you will be asked to create one first --
use this same email address, or the invitation will not match.

If you were not expecting this, you can ignore it. The link expires on its own.
`, inviterEmail, tenantName, link),
	}
}

// PasswordReset builds the "reset your password" email.
//
// The wording matters more than it looks. This email is the one an attacker
// triggers when they are probing somebody else's account, so it has to tell the
// real owner what happened WITHOUT implying they did something wrong, and it has
// to make clear that ignoring it is safe -- because ignoring it IS safe: the
// password does not change until the link is used.
func PasswordReset(baseURL, token string, ttlHours int) Message {
	link := fmt.Sprintf("%s/auth/password/reset?token=%s", baseURL, token)

	return Message{
		Subject: "Reset your password",
		Body: fmt.Sprintf(`Somebody asked to reset the password for this account.

Set a new password:

    %s

The link works once and expires in %d hour(s).

If this was not you, you do not need to do anything -- your password has not
changed, and it will not change unless somebody uses the link above.
`, link, ttlHours),
	}
}

// EmailVerification builds the "confirm your address" email.
//
// This one has to actually arrive, because the account cannot create a tenant
// until it does -- so keep the wording plain and the link obvious. Resist the urge
// to make it pretty; deliverability beats design for the one email that gates
// onboarding.
func EmailVerification(baseURL, token string, ttlHours int) Message {
	link := fmt.Sprintf("%s/auth/email/verify?token=%s", baseURL, token)

	return Message{
		Subject: "Confirm your email address",
		Body: fmt.Sprintf(`Confirm this email address to finish setting up your account:

    %s

The link works once and expires in %d hour(s).

You can sign in without it, but you will not be able to create anything until the
address is confirmed.

If you did not create an account, ignore this -- nothing will happen.
`, link, ttlHours),
	}
}
