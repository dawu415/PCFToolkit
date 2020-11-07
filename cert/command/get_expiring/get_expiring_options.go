package get_expiring

// Options hold the information for optional input flags for the GetExpiring Command
type Options struct {
	ContainsFilter               string
	MinimumMonthsWarningToExpire int
	ShowOk                       bool
}
