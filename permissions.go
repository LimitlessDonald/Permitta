package permitta

import (
	"fmt"
	constants "gitlab.com/launchbeaver/permitta/constants"
	"reflect"
	"strings"
	"time"
)

// TODO create dart client of this , when its recieving permissions in json
// todo permission check order allowed or not by CRUDE - > not allowed by user->not allowed by role -> not allowed by group -> allowed by user-> allowed by role -> allowed by group -> then  time based limits starting with atATime

// Permission is a very important struct that can be used as an embedded struct to control permissions for just about anything or used as a type, of a struct field
type Permission struct {
	Create  bool `json:"create"`
	Read    bool `json:"read"`
	Update  bool `json:"update"`
	Delete  bool `json:"delete"`
	Execute bool `json:"execute"`

	// START CREATE FIELDS
	//UsersNotAllowedToCreate         []string `json:"usersNotAllowedToCreate" ` //slice list of users allowed to create current item, could be unique id , or username, doesn't matter
	//RolesNotAllowedToCreate         []string `json:"rolesNotAllowedToCreate"`
	//GroupsNotAllowedToCreate        []string `json:"groupsNotAllowedToCreate"`
	//DomainsNotAllowedToCreate       []string `json:"domainsNotAllowedToCreate"`
	//OrganizationsNotAllowedToCreate []string `json:"organizationsNotAllowedToCreate"`
	//
	//UsersAllowedToCreate         []string `json:"usersAllowedToCreate" ` //slice list of users allowed to create current item, could be unique id , or username, doesn't matter
	//RolesAllowedToCreate         []string `json:"rolesAllowedToCreate"`
	//GroupsAllowedToCreate        []string `json:"groupsAllowedToCreate"`
	//DomainsAllowedToCreate       []string `json:"domainsAllowedToCreate"`
	//OrganizationsAllowedToCreate []string `json:"organizationsAllowedToCreate"`

	CreateLimitAllTime        uint   `json:"createLimitAllTime"` // Can be used to control how many of an item can be stored . For example the total file size you can have stored at any time is 5GB , not to be confused with CreateLimitAtATime
	CreateLimitAtATime        uint   `json:"createLimitAtATime"` // Can be used to limit how many of an item can be created at once, or at a time, for example limiting a user to adding 5 files at once . If this value is 5, the user won't be able to create more than 5 items at once
	CreateLimitPerMinute      uint   `json:"createLimitPerMinute"`
	CreateLimitPerHour        uint   `json:"createLimitPerHour"`
	CreateLimitPerDay         uint   `json:"createLimitPerDay"`
	CreateLimitPerWeek        uint   `json:"createLimitPerWeek"`
	CreateLimitPerFortnight   uint   `json:"createLimitPerFortnight"` //to limit items that can be created every two weeks
	CreateLimitPerMonth       uint   `json:"createLimitPerMonth"`     // Limit for every 30 days from FirstCreateTime  //todo, does it make sense to use FirstCreateTime or LastCreateTime
	CreateLimitPerQuarter     uint   `json:"createLimitPerQuarter"`   // 3 months, 90 days
	CreateLimitPerYear        uint   `json:"createLimitPerYear"`
	CreateLimitCustomDuration string `json:"createLimitCustomDuration"` // can be used to control very fine-grained custom limit , it takes the form "per_uint_duration" , e.g "per_5_minutes"

	// END CREATE FIELDS

	// START READ FIELDS
	//UsersNotAllowedToRead         []string `json:"usersNotAllowedToRead" `
	//RolesNotAllowedToRead         []string `json:"rolesNotAllowedToRead"`
	//GroupsNotAllowedToRead        []string `json:"groupsNotAllowedToRead"`
	//DomainsNotAllowedToRead       []string `json:"domainsNotAllowedToRead"`
	//OrganizationsNotAllowedToRead []string `json:"organizationsNotAllowedToRead"`
	//
	//UsersAllowedToRead         []string `json:"usersAllowedToRead" `
	//RolesAllowedToRead         []string `json:"rolesAllowedToRead"`
	//GroupsAllowedToRead        []string `json:"groupsAllowedToRead"`
	//DomainsAllowedToRead       []string `json:"domainsAllowedToRead"`
	//OrganizationsAllowedToRead []string `json:"organizationsAllowedToRead"`

	ReadLimitAllTime        uint   `json:"readLimitAllTime"` // Can be used to control how many of an item can be stored . For example the total file size you can have stored at any time is 5GB , not to be confused with ReadLimitAtATime
	ReadLimitAtATime        uint   `json:"readLimitAtATime"` // Can be used to limit how many of an item can be read at once, or at a time, for example limiting a user to adding 5 files at once . If this value is 5, the user won't be able to read more than 5 items at once
	ReadLimitPerMinute      uint   `json:"readLimitPerMinute"`
	ReadLimitPerHour        uint   `json:"readLimitPerHour"`
	ReadLimitPerDay         uint   `json:"readLimitPerDay"`
	ReadLimitPerWeek        uint   `json:"readLimitPerWeek"`
	ReadLimitPerFortnight   uint   `json:"readLimitPerFortnight"` //to limit items that can be read every two weeks
	ReadLimitPerMonth       uint   `json:"readLimitPerMonth"`     // Limit for every 30 days from FirstReadTime  //todo, does it make sense to use FirstReadTime or LastReadTime
	ReadLimitPerQuarter     uint   `json:"readLimitPerQuarter"`   // 3 months, 90 days
	ReadLimitPerYear        uint   `json:"readLimitPerYear"`
	ReadLimitCustomDuration string `json:"readLimitCustomDuration"` // can be used to control very fine-grained custom limit , it takes the form "per_uint_duration" , e.g "per_5_minutes"

	// END READ FIELDS

	// START UPDATE FIELDS
	//UsersNotAllowedToUpdate         []string `json:"usersNotAllowedToUpdate" `
	//RolesNotAllowedToUpdate         []string `json:"rolesNotAllowedToUpdate"`
	//GroupsNotAllowedToUpdate        []string `json:"groupsNotAllowedToUpdate"`
	//DomainsNotAllowedToUpdate       []string `json:"domainsNotAllowedToUpdate"`
	//OrganizationsNotAllowedToUpdate []string `json:"organizationsNotAllowedToUpdate"`
	//
	//UsersAllowedToUpdate         []string `json:"usersAllowedToUpdate" `
	//RolesAllowedToUpdate         []string `json:"rolesAllowedToUpdate"`
	//GroupsAllowedToUpdate        []string `json:"groupsAllowedToUpdate"`
	//DomainsAllowedToUpdate       []string `json:"domainsAllowedToUpdate"`
	//OrganizationsAllowedToUpdate []string `json:"organizationsAllowedToUpdate"`

	UpdateLimitAllTime        uint   `json:"updateLimitAllTime"` // Can be used to control how many of an item can be stored . For example the total file size you can have stored at any time is 5GB , not to be confused with UpdateLimitAtATime
	UpdateLimitAtATime        uint   `json:"updateLimitAtATime"` // Can be used to limit how many of an item can be updated at once, or at a time, for example limiting a user to adding 5 files at once . If this value is 5, the user won't be able to update more than 5 items at once
	UpdateLimitPerMinute      uint   `json:"updateLimitPerMinute"`
	UpdateLimitPerHour        uint   `json:"updateLimitPerHour"`
	UpdateLimitPerDay         uint   `json:"updateLimitPerDay"`
	UpdateLimitPerWeek        uint   `json:"updateLimitPerWeek"`
	UpdateLimitPerFortnight   uint   `json:"updateLimitPerFortnight"` //to limit items that can be updated every two weeks
	UpdateLimitPerMonth       uint   `json:"updateLimitPerMonth"`     // Limit for every 30 days from FirstUpdateTime  //todo, does it make sense to use FirstUpdateTime or LastUpdateTime
	UpdateLimitPerQuarter     uint   `json:"updateLimitPerQuarter"`   // 3 months, 90 days
	UpdateLimitPerYear        uint   `json:"updateLimitPerYear"`
	UpdateLimitCustomDuration string `json:"updateLimitCustomDuration"` // can be used to control very fine-grained custom limit , it takes the form "per_uint_duration" , e.g "per_5_minutes"

	// END UPDATE FIELDS

	// START DELETE FIELDS
	//UsersNotAllowedToDelete         []string `json:"usersNotAllowedToDelete" `
	//RolesNotAllowedToDelete         []string `json:"rolesNotAllowedToDelete"`
	//GroupsNotAllowedToDelete        []string `json:"groupsNotAllowedToDelete"`
	//DomainsNotAllowedToDelete       []string `json:"domainsNotAllowedToDelete"`
	//OrganizationsNotAllowedToDelete []string `json:"organizationsNotAllowedToDelete"`
	//
	//UsersAllowedToDelete         []string `json:"usersAllowedToDelete" `
	//RolesAllowedToDelete         []string `json:"rolesAllowedToDelete"`
	//GroupsAllowedToDelete        []string `json:"groupsAllowedToDelete"`
	//DomainsAllowedToDelete       []string `json:"domainsAllowedToDelete"`
	//OrganizationsAllowedToDelete []string `json:"organizationsAllowedToDelete"`

	DeleteLimitAllTime        uint   `json:"deleteLimitAllTime"` // Can be used to control how many of an item can be stored . For example the total file size you can have stored at any time is 5GB , not to be confused with DeleteLimitAtATime
	DeleteLimitAtATime        uint   `json:"deleteLimitAtATime"` // Can be used to limit how many of an item can be deleted at once, or at a time, for example limiting a user to adding 5 files at once . If this value is 5, the user won't be able to delete more than 5 items at once
	DeleteLimitPerMinute      uint   `json:"deleteLimitPerMinute"`
	DeleteLimitPerHour        uint   `json:"deleteLimitPerHour"`
	DeleteLimitPerDay         uint   `json:"deleteLimitPerDay"`
	DeleteLimitPerWeek        uint   `json:"deleteLimitPerWeek"`
	DeleteLimitPerFortnight   uint   `json:"deleteLimitPerFortnight"` //to limit items that can be deleted every two weeks
	DeleteLimitPerMonth       uint   `json:"deleteLimitPerMonth"`     // Limit for every 30 days from FirstDeleteTime  //todo, does it make sense to use FirstDeleteTime or LastDeleteTime
	DeleteLimitPerQuarter     uint   `json:"deleteLimitPerQuarter"`   // 3 months, 90 days
	DeleteLimitPerYear        uint   `json:"deleteLimitPerYear"`
	DeleteLimitCustomDuration string `json:"deleteLimitCustomDuration"` // can be used to control very fine-grained custom limit , it takes the form "per_uint_duration" , e.g "per_5_minutes"

	// END DELETE FIELDS

	// START EXECUTE FIELDS
	//UsersNotAllowedToExecute         []string `json:"usersNotAllowedToExecute" `
	//RolesNotAllowedToExecute         []string `json:"rolesNotAllowedToExecute"`
	//GroupsNotAllowedToExecute        []string `json:"groupsNotAllowedToExecute"`
	//DomainsNotAllowedToExecute       []string `json:"domainsNotAllowedToExecute"`
	//OrganizationsNotAllowedToExecute []string `json:"organizationsNotAllowedToExecute"`
	//
	//UsersAllowedToExecute         []string `json:"usersAllowedToExecute" `
	//RolesAllowedToExecute         []string `json:"rolesAllowedToExecute"`
	//GroupsAllowedToExecute        []string `json:"groupsAllowedToExecute"`
	//DomainsAllowedToExecute       []string `json:"domainsAllowedToExecute"`
	//OrganizationsAllowedToExecute []string `json:"organizationsAllowedToExecute"`

	ExecuteLimitAllTime        uint   `json:"executeLimitAllTime"` // Can be used to control how many of an item can be stored . For example the total file size you can have stored at any time is 5GB , not to be confused with ExecuteLimitAtATime
	ExecuteLimitAtATime        uint   `json:"executeLimitAtATime"` // Can be used to limit how many of an item can be executed at once, or at a time, for example limiting a user to adding 5 files at once . If this value is 5, the user won't be able to execute more than 5 items at once
	ExecuteLimitPerMinute      uint   `json:"executeLimitPerMinute"`
	ExecuteLimitPerHour        uint   `json:"executeLimitPerHour"`
	ExecuteLimitPerDay         uint   `json:"executeLimitPerDay"`
	ExecuteLimitPerWeek        uint   `json:"executeLimitPerWeek"`
	ExecuteLimitPerFortnight   uint   `json:"executeLimitPerFortnight"` //to limit items that can be executed every two weeks
	ExecuteLimitPerMonth       uint   `json:"executeLimitPerMonth"`     // Limit for every 30 days from FirstExecuteTime  //todo, does it make sense to use FirstExecuteTime or LastExecuteTime
	ExecuteLimitPerQuarter     uint   `json:"executeLimitPerQuarter"`   // 3 months, 90 days
	ExecuteLimitPerYear        uint   `json:"executeLimitPerYear"`
	ExecuteLimitCustomDuration string `json:"executeLimitCustomDuration"` // can be used to control very fine-grained custom limit , it takes the form "per_uint_duration" , e.g "per_5_minutes"

	// END EXECUTE FIELDS

}

type PermissionUsage struct {
	// START CREATE FIELDS
	FirstCreateTime                         time.Time `json:"firstCreateTime"`
	LastCreateTime                          time.Time `json:"lastCreateTime"`
	LastCreateQuantity                      uint      `json:"lastCreateQuantity"`
	TotalCreatedWithinTheLastMinute         uint      `json:"totalCreatedWithinTheLastMinute"`
	TotalCreatedWithinTheLastHour           uint      `json:"totalCreatedWithinTheLastHour"`
	TotalCreatedWithinTheLastDay            uint      `json:"totalCreatedWithinTheLastDay"`
	TotalCreatedWithinTheLastWeek           uint      `json:"totalCreatedWithinTheLastWeek"`
	TotalCreatedWithinTheLastFortnight      uint      `json:"totalCreatedWithinTheLastFortnight"`
	TotalCreatedWithinTheLastMonth          uint      `json:"totalCreatedWithinTheLastMonth"`
	TotalCreatedWithinTheLastQuarter        uint      `json:"totalCreatedWithinTheLastQuarter"`
	TotalCreatedWithinTheLastYear           uint      `json:"totalCreatedWithinTheLastYear"`
	TotalCreatedWithinTheLastCustomDuration string    // can be used to record usage that happened within a custom time frame it takes the form "last_uint_duration" e.g "last_10_minutes"
	//END CREATE FIELDS

	//START READ FIELDS
	FirstReadTime                        time.Time `json:"firstReadTime"`
	LastReadTime                         time.Time `json:"lastReadTime"`
	LastReadQuantity                     uint      `json:"lastReadQuantity"`
	TotalReadWithinTheLastMinute         uint      `json:"totalReadWithinTheLastMinute"`
	TotalReadWithinTheLastHour           uint      `json:"totalReadWithinTheLastHour"`
	TotalReadWithinTheLastDay            uint      `json:"totalReadWithinTheLastDay"`
	TotalReadWithinTheLastWeek           uint      `json:"totalReadWithinTheLastWeek"`
	TotalReadWithinTheLastFortnight      uint      `json:"totalReadWithinTheLastFortnight"`
	TotalReadWithinTheLastMonth          uint      `json:"totalReadWithinTheLastMonth"`
	TotalReadWithinTheLastQuarter        uint      `json:"totalReadWithinTheLastQuarter"`
	TotalReadWithinTheLastYear           uint      `json:"totalReadWithinTheLastYear"`
	TotalReadWithinTheLastCustomDuration string    // can be used to record usage that happened within a custom time frame it takes the form "last_uint_duration" e.g "last_10_minutes"
	//END READ FIELDS

	// START UPDATE FIELDS
	FirstUpdateTime                         time.Time `json:"firstUpdateTime"`
	LastUpdateTime                          time.Time `json:"lastUpdateTime"`
	LastUpdateQuantity                      uint      `json:"lastUpdateQuantity"`
	TotalUpdatedWithinTheLastMinute         uint      `json:"totalUpdatedWithinTheLastMinute"`
	TotalUpdatedWithinTheLastHour           uint      `json:"totalUpdatedWithinTheLastHour"`
	TotalUpdatedWithinTheLastDay            uint      `json:"totalUpdatedWithinTheLastDay"`
	TotalUpdatedWithinTheLastWeek           uint      `json:"totalUpdatedWithinTheLastWeek"`
	TotalUpdatedWithinTheLastFortnight      uint      `json:"totalUpdatedWithinTheLastFortnight"`
	TotalUpdatedWithinTheLastMonth          uint      `json:"totalUpdatedWithinTheLastMonth"`
	TotalUpdatedWithinTheLastQuarter        uint      `json:"totalUpdatedWithinTheLastQuarter"`
	TotalUpdatedWithinTheLastYear           uint      `json:"totalUpdatedWithinTheLastYear"`
	TotalUpdatedWithinTheLastCustomDuration string    // can be used to record usage that happened within a custom time frame it takes the form "last_uint_duration" e.g "last_10_minutes"
	//END UPDATE FIELDS

	//START DELETE FIELDS
	FirstDeleteTime                         time.Time `json:"firstDeleteTime"`
	LastDeleteTime                          time.Time `json:"lastDeleteTime"`
	LastDeleteQuantity                      uint      `json:"lastDeleteQuantity"`
	TotalDeletedWithinTheLastMinute         uint      `json:"totalDeletedWithinTheLastMinute"`
	TotalDeletedWithinTheLastHour           uint      `json:"totalDeletedWithinTheLastHour"`
	TotalDeletedWithinTheLastDay            uint      `json:"totalDeletedWithinTheLastDay"`
	TotalDeletedWithinTheLastWeek           uint      `json:"totalDeletedWithinTheLastWeek"`
	TotalDeletedWithinTheLastFortnight      uint      `json:"totalDeletedWithinTheLastFortnight"`
	TotalDeletedWithinTheLastMonth          uint      `json:"totalDeletedWithinTheLastMonth"`
	TotalDeletedWithinTheLastQuarter        uint      `json:"totalDeletedWithinTheLastQuarter"`
	TotalDeletedWithinTheLastYear           uint      `json:"totalDeletedWithinTheLastYear"`
	TotalDeletedWithinTheLastCustomDuration string    // can be used to record usage that happened within a custom time frame it takes the form "last_uint_duration" e.g "last_10_minutes"
	//END DELETE FIELDS

	//START EXECUTE FIELDS
	FirstExecuteTime                         time.Time `json:"firstExecuteTime"`
	LastExecuteTime                          time.Time `json:"lastExecuteTime"`
	LastExecuteQuantity                      uint      `json:"lastExecuteQuantity"`
	TotalExecutedWithinTheLastMinute         uint      `json:"totalExecutedWithinTheLastMinute"`
	TotalExecutedWithinTheLastHour           uint      `json:"totalExecutedWithinTheLastHour"`
	TotalExecutedWithinTheLastDay            uint      `json:"totalExecutedWithinTheLastDay"`
	TotalExecutedWithinTheLastWeek           uint      `json:"totalExecutedWithinTheLastWeek"`
	TotalExecutedWithinTheLastFortnight      uint      `json:"totalExecutedWithinTheLastFortnight"`
	TotalExecutedWithinTheLastMonth          uint      `json:"totalExecutedWithinTheLastMonth"`
	TotalExecutedWithinTheLastQuarter        uint      `json:"totalExecutedWithinTheLastQuarter"`
	TotalExecutedWithinTheLastYear           uint      `json:"totalExecutedWithinTheLastYear"`
	TotalExecutedWithinTheLastCustomDuration string    // can be used to record usage that happened within a custom time frame it takes the form "last_uint_duration" e.g "last_10_minutes"
	//END EXECUTE FIELDS

}

// PermissionRequestData is a struct that holds data concerning the permission request . It includes things like users,roles,groups,actionType(constants.ActionTypeCreate|constants.ActionTypeRead....) etc. necessary to help get permission status
type PermissionRequestData struct {
	ActionType              string
	UserEntityPermissions   Permission
	RoleEntityPermissions   Permission
	GroupEntityPermissions  Permission
	DomainEntityPermissions Permission
	OrgEntityPermissions    Permission //Organization EntityPermissions
	PermissionOrder         string     // the flow in which the permission should take e.g org->domain->group->role->user //default order is org->
}

// PermissionWithUsageRequestData to hold permission data and also check permission against usage and limits, so if actionQuantity + usage exceeds limit, deny access, but if its less or equal to grant access, hope you get the gist
type PermissionWithUsageRequestData struct {
	PermissionRequestData
	ActionQuantity    uint
	UserEntityUsage   uint
	RoleEntityUsage   uint
	GroupEntityUsage  uint
	DomainEntityUsage uint
	OrgEntityUsage    uint
}

func IsActionPermitted(permissionRequestData PermissionRequestData) bool {
	actionType := permissionRequestData.ActionType
	permissionOrder := strings.TrimSpace(permissionRequestData.PermissionOrder)
	var permissions Permission
	var emptyPermission Permission
	finalPermittedValue := false

	// only allow CRUDE(Create, Read, Update, Delete,Execute) action types
	if isActionTypeValid(actionType) == false {
		return false
	}
	// let's split the order and loop through it to get each entity action permission,
	// if permission is granted in one entity / order level, go to the next , if all is granted and the loop is at the last point and the last one is granted, grant permission else, deny permission
	//if permissionOrder is empty use default
	if permissionOrder == "" || len(permissionOrder) == 0 {
		permissionOrder = constants.DefaultPermissionOrder
	}
	// ensure the order contains the separator first , before attempting to split
	if len(permissionOrder) >= constants.MinimumPermissionOrderLength && strings.Contains(permissionOrder, constants.OrderSeparator) {
		splitOrder := strings.Split(permissionOrder, constants.OrderSeparator)
		if len(splitOrder) > 0 {
			//loop through the split order and check permission for each entity as arranged in the order
			for i := 0; i < len(splitOrder); i++ {
				currentEntity := splitOrder[i]
				switch currentEntity {
				case constants.EntityOrg:
					permissions = permissionRequestData.OrgEntityPermissions
					break
				case constants.EntityDomain:
					permissions = permissionRequestData.DomainEntityPermissions
					break
				case constants.EntityGroup:
					permissions = permissionRequestData.GroupEntityPermissions
					break
				case constants.EntityRole:
					permissions = permissionRequestData.RoleEntityPermissions
					break
				case constants.EntityUser:
					permissions = permissionRequestData.UserEntityPermissions
					break
				default:
					permissions = Permission{}
					break
				}

				// check if permissions is empty, if its empty continue
				if permissions == emptyPermission {
					continue
				}

				isCurrentEntityPermitted := IsEntityActionPermitted(actionType, permissions)
				if isCurrentEntityPermitted == false {
					return false
				}
				// if current entity is permitted, and we are not on the last entity in the order, continue
				if (isCurrentEntityPermitted == true) && (i != len(splitOrder)-1) {
					// its important we set final permitted to true here, because if this entity action type in the order is filled and permitted , but all other proceeding entity Permission struct are empty, it would give a wrong result
					//So we need to save current permission value as true , in case other permission data are empty
					// NOTE that empty is not same as false, if the actionType we are checking for proceeding permission structs is not empty and marked as false, the condition above would return false
					finalPermittedValue = true
					continue
				}
				// if current entity is permitted, and it's the last entity in the order, return true
				if (isCurrentEntityPermitted == true) && (i == len(splitOrder)-1) {
					return true
				}
			}
		}
	}

	fmt.Println("Hala 1")
	return finalPermittedValue
}

//todo [LATER] optimise this function , its looping through the permissions twice

// IsActionPermittedWithUsage is a function to check if action is permitted, then it checks the usage following the PermissionRequestData.PermissionOrder
// It loops through each entity in the order and checks permission against request usage + actionQuantity for each limit type
// WHat does this mean let's say our request data is like this :
/**
 data:= PermissionWithUsageRequestData  {
	PermissionRequestData : PermissionRequestData {
			ActionType : "create"
			UserEntityPermissions: userPermission
			RoleEntityPermissions :  rolePermission
			GroupEntityPermissions:  Permission
			DomainEntityPermissions Permission
			OrgEntityPermissions    Permission //Organization Permissions
			PermissionOrder   string
		}
	ActionQuantity uint
	Usage          PermissionUsage
}

*/
func IsActionPermittedWithUsage(requestData PermissionWithUsageRequestData) bool {
	// first check if action is permitted based on the actionType
	isActionPermitted := IsActionPermitted(requestData.PermissionRequestData)
	if isActionPermitted == false {
		return false
	}

	// Loop through all the usage according to the order
	if isActionPermitted == true {

	}

	return false
}

func IsEntityActionPermitted(actionType string, entityPermissions Permission) bool {
	// ensure the action type is correct
	if isActionTypeValid(actionType) == false {
		return false
	}
	// the name of the struct field of the action type, whether its Create,Read....
	structFieldName := firstLetterToUppercase(actionType)
	//case as bool
	structFieldValue, _ := getValueFromStructFieldByName(entityPermissions, structFieldName)
	if structFieldValue == nil {
		fmt.Printf("Something went wrong getting the struct field value for %s \n\n", structFieldName)
		return false
	} else {
		//Attempt to cast value as bool , since the CRUDE fields are bool
		isPermitted := structFieldValue.(bool)
		return isPermitted
	}

}

func isActionTypeValid(actionType string) bool {
	// ensure the action type is correct
	if actionType != constants.ActionTypeCreate &&
		actionType != constants.ActionTypeRead &&
		actionType != constants.ActionTypeUpdate &&
		actionType != constants.ActionTypeDelete &&
		actionType != constants.ActionTypeExecute {
		return false
	}

	return true
}

//func getActionFieldName(actionType string)string{
//	// ensure the action type is correct
//	if isActionTypeValid(actionType)==false{
//		return ""
//	}
//	// the name of the struct field of the action type, whether its Create,Read....
//
//	structFieldName:=""
//	switch actionType {
//	case constants.ActionTypeCreate: structFieldName:="Create"
//	break
//	case constants.ActionTypeRead: structFieldName:="Read"
//	break
//
//	}
//}

func firstLetterToUppercase(s string) string {
	return strings.ToUpper(string(s[0])) + s[1:]

}

func getValueFromStructFieldByName(s interface{}, fieldName string) (interface{}, error) {
	rv := reflect.ValueOf(s)
	if rv.Kind() != reflect.Struct {
		return nil, fmt.Errorf("input is not a struct")
	}
	field := rv.FieldByName(fieldName)
	if !field.IsValid() {
		return nil, fmt.Errorf("field '%s' not found", fieldName)
	}
	return field.Interface(), nil
}
