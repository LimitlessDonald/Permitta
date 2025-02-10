package permitta

import (
	"strconv"
	"testing"
)

var SampleOrgPermission = Permission{
	Create:  true,
	Read:    true,
	Update:  false,
	Delete:  false,
	Execute: true,
	CreateActionLimits: ActionLimit{
		AllTimeLimit:         0,
		BatchLimit:           1,
		PerMinuteLimit:       0,
		PerHourLimit:         0,
		PerDayLimit:          0,
		PerWeekLimit:         0,
		PerFortnightLimit:    0,
		PerMonthLimit:        0,
		PerQuarterLimit:      0,
		PerYearLimit:         0,
		CustomDurationsLimit: nil,
	},
	ReadActionLimits: ActionLimit{
		AllTimeLimit:         0,
		BatchLimit:           2,
		PerMinuteLimit:       0,
		PerHourLimit:         0,
		PerDayLimit:          0,
		PerWeekLimit:         0,
		PerFortnightLimit:    0,
		PerMonthLimit:        0,
		PerQuarterLimit:      0,
		PerYearLimit:         0,
		CustomDurationsLimit: nil,
	},
}

var SampleUserPermission = Permission{
	Create:  false,
	Read:    true,
	Update:  false,
	Delete:  false,
	Execute: true,
	CreateActionLimits: ActionLimit{
		AllTimeLimit:         0,
		BatchLimit:           1,
		PerMinuteLimit:       0,
		PerHourLimit:         0,
		PerDayLimit:          0,
		PerWeekLimit:         0,
		PerFortnightLimit:    0,
		PerMonthLimit:        0,
		PerQuarterLimit:      0,
		PerYearLimit:         0,
		CustomDurationsLimit: nil,
	},
	ReadActionLimits: ActionLimit{
		AllTimeLimit:         5,
		BatchLimit:           2,
		PerMinuteLimit:       0,
		PerHourLimit:         0,
		PerDayLimit:          0,
		PerWeekLimit:         0,
		PerFortnightLimit:    0,
		PerMonthLimit:        0,
		PerQuarterLimit:      0,
		PerYearLimit:         0,
		CustomDurationsLimit: nil,
	},
}

func TestIsActionPermitted(t *testing.T) {
	permissionRequestData := PermissionRequestData{
		ActionType:              "read",
		UserEntityPermissions:   Permission{},
		RoleEntityPermissions:   Permission{},
		GroupEntityPermissions:  Permission{},
		DomainEntityPermissions: Permission{},
		OrgEntityPermissions:    Permission{},
		EntityPermissionOrder:   "org->user",
	}
	isActionPermitted := IsActionPermitted(permissionRequestData)
	//if isActionPermitted == true {
	t.Errorf("Expected true got %s", strconv.FormatBool(isActionPermitted))
	//}
}

func TestIsActionPermittedWithUsage(t *testing.T) {
	permissionRequestData := PermissionWithUsageRequestData{
		PermissionRequestData: PermissionRequestData{
			ActionType:              "read",
			UserEntityPermissions:   SampleUserPermission,
			RoleEntityPermissions:   Permission{},
			GroupEntityPermissions:  Permission{},
			DomainEntityPermissions: Permission{},
			OrgEntityPermissions:    SampleOrgPermission,
			EntityPermissionOrder:   "org->user",
		},
		ActionQuantity:    2,
		UserEntityUsage:   PermissionUsage{},
		RoleEntityUsage:   PermissionUsage{},
		GroupEntityUsage:  PermissionUsage{},
		DomainEntityUsage: PermissionUsage{},
		OrgEntityUsage:    PermissionUsage{},
	}

	isActionPermittedWithUsage := IsActionPermittedWithUsage(permissionRequestData)
	t.Errorf("Expected true got %s", strconv.FormatBool(isActionPermittedWithUsage))
}
