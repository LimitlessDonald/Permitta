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
	CreateOperationLimits: OperationLimit{
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
	ReadOperationLimits: OperationLimit{
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
	CreateOperationLimits: OperationLimit{
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
	ReadOperationLimits: OperationLimit{
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

func TestIsOperationPermitted(t *testing.T) {
	permissionRequestData := PermissionRequestData{
		Operation:               "read",
		UserEntityPermissions:   Permission{},
		RoleEntityPermissions:   Permission{},
		GroupEntityPermissions:  Permission{},
		DomainEntityPermissions: Permission{},
		OrgEntityPermissions:    Permission{},
		EntityPermissionOrder:   "org->user",
	}
	isOperationPermitted := IsOperationPermitted(permissionRequestData)
	//if isOperationPermitted == true {
	t.Errorf("Expected true got %s", strconv.FormatBool(isOperationPermitted))
	//}
}

func TestIsOperationPermittedWithUsage(t *testing.T) {
	permissionRequestData := PermissionWithUsageRequestData{
		PermissionRequestData: PermissionRequestData{
			Operation:               "read",
			UserEntityPermissions:   SampleUserPermission,
			RoleEntityPermissions:   Permission{},
			GroupEntityPermissions:  Permission{},
			DomainEntityPermissions: Permission{},
			OrgEntityPermissions:    SampleOrgPermission,
			EntityPermissionOrder:   "org->user",
		},
		OperationQuantity: 2,
		UserEntityUsage:   PermissionUsage{},
		RoleEntityUsage:   PermissionUsage{},
		GroupEntityUsage:  PermissionUsage{},
		DomainEntityUsage: PermissionUsage{},
		OrgEntityUsage:    PermissionUsage{},
	}

	isOperationPermittedWithUsage := IsOperationPermittedWithUsage(permissionRequestData)
	t.Errorf("Expected true got %s", strconv.FormatBool(isOperationPermittedWithUsage))
}

func TestNotationToPermission(t *testing.T) {
	notationString := "cr-d-|c=all:20|r=all:10,batch:4,minute:3,hour:5,day:70,week:400,fortnight:600,month:1000,year:9000|"
	permission := NotationToPermission(notationString)
	jsonString, _ := json.Marshal(permission)
	t.Errorf("Got \n %s", jsonString)

}
