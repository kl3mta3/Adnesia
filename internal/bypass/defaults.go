package bypass

// defaultPatterns is the built-in passthrough list: hosts Adnesia should NOT
// intercept out of the box.
//
// The targets here are mostly NATIVE desktop apps and OS services that pin
// their certificates and will break (or refuse to connect) if they see a
// certificate signed by our local CA. Browser traffic to banks and the like
// is generally fine to intercept because browsers trust the installed root —
// so this list deliberately leans toward app/OS endpoints rather than trying
// to enumerate every bank.
//
// Users extend this via config (BypassDomains) or `-bypass-add`; nothing here
// can be removed, but anything added can.
var defaultPatterns = []string{
	// --- Windows / Microsoft core services ---
	"*.windowsupdate.com",
	"*.update.microsoft.com",
	"*.delivery.mp.microsoft.com",
	"*.msftncsi.com",
	"*.msftconnecttest.com",
	"login.microsoftonline.com",
	"login.live.com",
	"*.onedrive.com",
	"*.sharepoint.com",

	// --- Apple services (iCloud/iTunes for Windows) ---
	"*.apple.com",
	"*.icloud.com",
	"*.mzstatic.com",
	"*.push.apple.com",

	// --- Account/sign-in endpoints that commonly pin ---
	"accounts.google.com",

	// --- Password managers (desktop clients pin) ---
	"*.1password.com",
	"*.lastpass.com",
	"*.bitwarden.com",
	"*.dashlane.com",

	// --- Messaging apps (desktop clients pin) ---
	"*.whatsapp.com",
	"*.whatsapp.net",
	"*.signal.org",
	"*.telegram.org",
	"*.discord.com",
	"*.discordapp.com",
	"*.discord.gg",
	"*.slack.com",

	// --- Media / cloud desktop clients ---
	"*.spotify.com",
	"*.dropbox.com",
	"*.dropboxapi.com",

	// --- Game launchers (all pin heavily) ---
	"*.steampowered.com",
	"*.steamcommunity.com",
	"*.steamstatic.com",
	"*.epicgames.com",
	"*.ea.com",
	"*.battle.net",
	"*.blizzard.com",
	"*.riotgames.com",
}

// Defaults returns a copy of the built-in passthrough patterns.
func Defaults() []string {
	out := make([]string, len(defaultPatterns))
	copy(out, defaultPatterns)
	return out
}
