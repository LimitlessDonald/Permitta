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
}

func TestIsActionPermitted(t *testing.T) {
	permissionRequestData := PermissionRequestData{
		ActionType:              "create",
		UserEntityPermissions:   Permission{},
		RoleEntityPermissions:   Permission{},
		GroupEntityPermissions:  Permission{},
		DomainEntityPermissions: Permission{},
		OrgEntityPermissions:    SampleOrgPermission,
		PermissionOrder:         "",
	}
	isActionPermitted := IsActionPermitted(permissionRequestData)
	//if isActionPermitted == true {
	t.Errorf("Expected true got %s", strconv.FormatBool(isActionPermitted))
	//}
}
