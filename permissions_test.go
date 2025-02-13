package permitta

import (
	"encoding/json"
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

func TestNotationToPermission(t *testing.T) {
	notationString := "cr-d-|c=all:20|r=all:10,batch:4,minute:3,hour:5,day:70,week:400,fortnight:600,month:1000,year:9000|"
	permission := NotationToPermission(notationString)
	jsonString, _ := json.Marshal(permission)
	t.Errorf("Got \n %s", jsonString)

}
