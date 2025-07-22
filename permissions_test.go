package permitta

import (
	"encoding/json"
	"fmt"
	constants "github.com/limitlessdonald/permitta/constants"
	"strconv"
	"testing"
	"time"
)

var SampleOrgPermission = Permission{
	QuotaLimit: 10,
	Create:     true,
	Read:       true,
	Update:     false,
	Delete:     false,
	Execute:    true,
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

var SampleOrgNotation = NotationToPermission("cr--e|r=batch:2|q=60")
var SampleUserPermission = Permission{
	QuotaLimit: 3,
	Create:     true,
	Read:       true,
	Update:     false,
	Delete:     false,
	Execute:    true,
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

var SampleUserPermissionUsage = PermissionUsage{
	QuotaUsage: 5,
	CreateOperationUsages: OperationUsage{
		FirstTime:                    time.Date(2025, time.February, 28, 0, 0, 0, 0, time.Local),
		LastTime:                     time.Date(2024, time.March, 5, 00, 46, 0, 0, time.Local),
		LastQuantity:                 10,
		AllTime:                      1000000,
		WithinTheLastMinute:          5,
		WithinTheLastHour:            50,
		WithinTheLastDay:             500,
		WithinTheLastWeek:            5000,
		WithinTheLastFortnight:       10000,
		WithinTheLastMonth:           20000,
		WithinTheLastQuarter:         30000,
		WithinTheLastYear:            50000,
		WithinTheLastCustomDurations: nil,
	},
	ReadOperationUsages:    OperationUsage{},
	UpdateOperationUsages:  OperationUsage{},
	DeleteOperationUsages:  OperationUsage{},
	ExecuteOperationUsages: OperationUsage{},
}

func TestIsOperationPermitted(t *testing.T) {
	//fmt.Print(SampleOrgNotation)
	permissionRequestData := PermissionRequestData{
		Operation:               "read",
		UserEntityPermissions:   SampleUserPermission,
		RoleEntityPermissions:   Permission{},
		GroupEntityPermissions:  Permission{},
		DomainEntityPermissions: Permission{},
		OrgEntityPermissions:    SampleOrgPermission,
		EntityPermissionOrder:   "org->user",
	}
	isOperationPermitted := IsOperationPermitted(permissionRequestData)
	if isOperationPermitted == false {
		t.Errorf("Expected true got %s", strconv.FormatBool(isOperationPermitted))
	}
}

func TestIsOperationPermittedWithUsage(t *testing.T) {
	permissionRequestData := PermissionWithUsageRequestData{
		PermissionRequestData: PermissionRequestData{
			Operation:               "create",
			UserEntityPermissions:   SampleUserPermission,
			RoleEntityPermissions:   Permission{},
			GroupEntityPermissions:  Permission{},
			DomainEntityPermissions: Permission{},
			OrgEntityPermissions:    SampleOrgNotation,
			EntityPermissionOrder:   "org->user",
		},
		OperationQuantity: 1,
		UserEntityUsage: PermissionUsage{
			QuotaUsage:             2,
			CreateOperationUsages:  OperationUsage{},
			ReadOperationUsages:    OperationUsage{},
			UpdateOperationUsages:  OperationUsage{},
			DeleteOperationUsages:  OperationUsage{},
			ExecuteOperationUsages: OperationUsage{},
		},
		RoleEntityUsage:   PermissionUsage{},
		GroupEntityUsage:  PermissionUsage{},
		DomainEntityUsage: PermissionUsage{},
		OrgEntityUsage: PermissionUsage{
			QuotaUsage: 50,
		},
	}

	isOperationPermittedWithUsage := IsOperationPermittedWithUsage(permissionRequestData)
	if isOperationPermittedWithUsage == false {
		t.Errorf("Expected true got %s", strconv.FormatBool(isOperationPermittedWithUsage))
	}

}

//func TestNotationToPermission(t *testing.T) {
//	notationString := "cr-d-|c=all:20|r=all:10,batch:4,minute:3,hour:5,day:70,week:400,fortnight:600,month:1000,year:9000|q=500"
//	permission := NotationToPermission(notationString)
//	jsonString, _ := json.Marshal(permission)
//	t.Errorf("Got \n %s", jsonString)
//
//}

//func TestGetOperationUsages(t *testing.T) {
//	fmt.Println("Sample sanitized usage")
//	fmt.Println(GetOperationUsages(constants.OperationCreate, SampleUserPermissionUsage))
//}

func TestIsEntityOperationPermitted(t *testing.T) {
	//m|min|mins|minute|minutes|
	notation := "-rude|start=1752817851|end=1752821969|q=5|r=year:56"
	permission := NotationToPermission(notation)
	isOperationPermitted := IsEntityOperationPermitted(constants.OperationRead, permission)
	fmt.Printf("%+v\n", permission)
	if isOperationPermitted == false {
		t.Errorf("Simple permission check faileds")
	}
}

func TestPlayground(t *testing.T) {

	jsonBytes, err := json.Marshal(PermissionUsage{})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(jsonBytes))
}
