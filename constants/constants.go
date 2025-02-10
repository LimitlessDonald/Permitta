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
)

const (
	NotationSectionSeparator = "|"
)
