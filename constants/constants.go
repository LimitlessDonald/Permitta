package permittaConstants

const (
	MinimumPermissionOrderLength = 5
	OrderSeparator               = "->"
	DefaultPermissionOrder       = EntityOrg + OrderSeparator + EntityDomain + OrderSeparator + EntityGroup + OrderSeparator + EntityRole + OrderSeparator + EntityUser
	EntityOrg                    = "org"
	EntityDomain                 = "domain"
	EntityGroup                  = "group"
	EntityRole                   = "role"
	EntityUser                   = "user"
)
