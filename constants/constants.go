package permittaConstants

const (
	Unlimited                          = 0
	MinimumEntityPermissionOrderLength = 3
	OrderSeparator                     = "->"
	DefaultEntityPermissionOrder       = EntityOrg + OrderSeparator + EntityDomain + OrderSeparator + EntityGroup + OrderSeparator + EntityRole + OrderSeparator + EntityUser
	EntityOrg                          = "org"
	EntityDomain                       = "domain"
	EntityGroup                        = "group"
	EntityRole                         = "role"
	EntityUser                         = "user"
	ListOfAcceptedDurationsSeconds     = "s|sec|secs|second|seconds|"
	ListOfAcceptedDurationsMinutes     = "m|min|mins|minute|minutes|"
	ListOfAcceptedDurationsHours       = "h|hr|hour|hours|"
	ListOfAcceptedDurationsDays        = "d|day|days|"
	ListOfAcceptedDurationsWeek        = "w|week|weeks|"
	ListOfAcceptedDurationsMonth       = "M|mo|month|months|"
	ListOfAcceptedDurationsYear        = "y|yr|year|years"
	ListOfAcceptedDurations            = ListOfAcceptedDurationsSeconds + ListOfAcceptedDurationsMinutes + ListOfAcceptedDurationsHours + ListOfAcceptedDurationsDays + ListOfAcceptedDurationsWeek + ListOfAcceptedDurationsMonth + ListOfAcceptedDurationsYear
)

const (
	NotationSectionSeparator                = "|"
	NotationOperationLimitsSeparator        = ","
	NotationOperationLimitAndValueSeparator = ":"
	NotationCustomLimitValuePrefix          = "["
	NotationCustomLimitValueSuffix          = "]"
	NotationCustomLimitValueListSeparator   = "&"

	NotationOperationBatchLimitKey     = "batch"
	NotationOperationAllTimeLimitKey   = "all"
	NotationOperationMinuteLimitKey    = "minute"
	NotationOperationHourLimitKey      = "hour"
	NotationOperationDayLimitKey       = "day"
	NotationOperationWeekLimitKey      = "week"
	NotationOperationFortnightLimitKey = "fortnight"
	NotationOperationMonthLimitKey     = "month"
	NotationOperationQuarterLimitKey   = "quarter"
	NotationOperationYearLimitKey      = "year"
	NotationOperationCustomLimitKey    = "custom"
)
