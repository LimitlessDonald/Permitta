package permittaConstants

import "time"

const (
	Unlimited                          = 0
	UnlimitedString                    = "unlimited"
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

const (
	TimeDurationDay       = 24 * time.Hour        // we have 24 hours in a day
	TimeDurationWeek      = 7 * TimeDurationDay   // 7 days in a week
	TimeDurationFortnight = 14 * TimeDurationDay  // 14 days in a fortnight
	TimeDurationMonth     = 30 * TimeDurationDay  // 30 days in a month
	TimeDurationQuarter   = 90 * TimeDurationDay  // 90 days in a quarter
	TimeDurationYear      = 360 * TimeDurationDay // 360 days in a year

)
