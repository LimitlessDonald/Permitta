package permitta

import (
	"errors"
	"fmt"
	constants "gitlab.com/launchbeaver/permitta/constants"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TODO create dart client of this , when its recieving permissions in json

// Permission is a very important struct that can be used as an embedded struct to control permissions for just about anything or used as a type, of a struct field
type Permission struct {
	// QuotaLimit is a way to place a HARD limit of how much of the resource can exist at any given time
	// This is not to be confused with AllTimeLimit of each operation
	// Here is a good real world scenario. If I set a file  QuotaLimit of 100GB , I can't have more than 100GB of files saved , but I could have a CreateOperation AllTimeLimit of 1TB , this means I can create up to a maximum total files of 1TB , as long as I delete excess files before creating new ones
	// Every time I delete(Delete Operation) a resource (files in this case), I reduce the QuotaUsage by the OperationQuantity , when I create(Create Operation) , I also increase the QuotaUsage by the OperationQuantity
	// If QuotaLimit is 0, this means it's unlimited , so a unlimited number of resource can exist, this also implies that Create Operation is essentially unlimited, BUT the duration based limits and AllTime limit would still take effect
	QuotaLimit uint
	Create     bool `json:"create"`
	Read       bool `json:"read"`
	Update     bool `json:"update"`
	Delete     bool `json:"delete"`
	Execute    bool `json:"execute"`

	CreateOperationLimits  OperationLimit `json:"createOperationLimits"`
	ReadOperationLimits    OperationLimit `json:"readOperationLimits"`
	UpdateOperationLimits  OperationLimit `json:"updateOperationLimits"`
	DeleteOperationLimits  OperationLimit `json:"deleteOperationLimits"`
	ExecuteOperationLimits OperationLimit `json:"executeOperationLimits"`
}

type OperationLimit struct {
	BatchLimit           uint     `json:"batchLimit"`   // Can be used to limit how many of an item can be deleted at once, or at a time, for example limiting a user to adding 5 files at once . If this value is 5, the user won't be able to delete more than 5 items at once. Batch can't be 0 which denotes unlimited, it has to be 1 or above, the default value if not set won't be 0, but 1
	AllTimeLimit         uint     `json:"allTimeLimit"` // Can be used to control how many of an item can be created all Time
	PerMinuteLimit       uint     `json:"perMinuteLimit"`
	PerHourLimit         uint     `json:"perHourLimit"`
	PerDayLimit          uint     `json:"perDayLimit"`
	PerWeekLimit         uint     `json:"perWeekLimit"`
	PerFortnightLimit    uint     `json:"perFortnightLimit"` //to limit items that can be deleted every two weeks
	PerMonthLimit        uint     `json:"perMonthLimit"`     // Limit for every 30 days from FirstDeleteTime  //todo, does it make sense to use FirstDeleteTime or LastDeleteTime
	PerQuarterLimit      uint     `json:"perQuarterLimit"`   // 3 months, 90 days
	PerYearLimit         uint     `json:"perYearLimit"`
	CustomDurationsLimit []string `json:"customDurationsLimit"`
}

// getBatchLimit is useful for setting the default batch limit to 1 if its 0, because batch limit can't be unlimited
func (operationLimit *OperationLimit) getBatchLimit() uint {
	if operationLimit.BatchLimit < 1 {
		return 1
	}
	return operationLimit.BatchLimit
}

// setDefaultLimits is useful for setting the default batch limit to 1 if its 0, because batch limit can't be unlimited
func (operationLimit *OperationLimit) setDefaultLimits() {
	if operationLimit.BatchLimit < 1 {
		operationLimit.BatchLimit = 1
	}

}

type OperationUsage struct {
	FirstTime                    time.Time `json:"firstTime"`
	LastTime                     time.Time `json:"lastTime"`
	LastQuantity                 uint      `json:"lastQuantity"`
	AllTime                      uint      `json:"allTime"`
	WithinTheLastMinute          uint      `json:"withinTheLastMinute"`
	WithinTheLastHour            uint      `json:"withinTheLastHour"`
	WithinTheLastDay             uint      `json:"withinTheLastDay"`
	WithinTheLastWeek            uint      `json:"withinTheLastWeek"`
	WithinTheLastFortnight       uint      `json:"withinTheLastFortnight"`
	WithinTheLastMonth           uint      `json:"withinTheLastMonth"`
	WithinTheLastQuarter         uint      `json:"withinTheLastQuarter"`
	WithinTheLastYear            uint      `json:"withinTheLastYear"`
	WithinTheLastCustomDurations []string  `json:"withinTheLastCustomDurations"`
}

// sanitizeDurationUsage is a setter to  "sanitize" value of the usage durations
// We need limit duration setters because their value can't always be trusted for checking permission access
// what does this mean ?
// Take this case scenario , I have a limit of 5 files per minute , if I created/used 5 files within a minute, 2 days ago and the usage has not been updated since then and I have not created any file since 2 days
// the usage record would definitely still be 5, and I won't be allowed access , so we want to check LastTime and compare it with operation request time, which is time.Now() , because the usage listed here, may have "expired" and we are no longer in the window of that duration
// in this specific case of "WithinMinute", if a minute has exceeded we need to reset the WithinTheLastXDuration usage
func (operationUsage *OperationUsage) sanitizeDurationUsage() {
	durationDiff := time.Now().Sub(operationUsage.LastTime)
	// let's start with within the last minute

	// if a minute has passed since the lastTime, reset the usage
	if durationDiff > time.Minute {
		operationUsage.WithinTheLastMinute = 0
	}

	if durationDiff > time.Hour {
		operationUsage.WithinTheLastHour = 0
	}

	if durationDiff > constants.TimeDurationDay {
		operationUsage.WithinTheLastDay = 0
	}

	if durationDiff > constants.TimeDurationWeek {
		operationUsage.WithinTheLastWeek = 0
	}

	if durationDiff > constants.TimeDurationFortnight {
		operationUsage.WithinTheLastFortnight = 0
	}

	if durationDiff > constants.TimeDurationMonth {
		operationUsage.WithinTheLastMonth = 0
	}

	if durationDiff > constants.TimeDurationQuarter {
		operationUsage.WithinTheLastQuarter = 0
	}

	if durationDiff > constants.TimeDurationYear {
		operationUsage.WithinTheLastYear = 0
	}

	//todo custom durations  operationUsage  sanitization

}

type PermissionUsage struct {
	QuotaUsage             uint
	CreateOperationUsages  OperationUsage
	ReadOperationUsages    OperationUsage
	UpdateOperationUsages  OperationUsage
	DeleteOperationUsages  OperationUsage
	ExecuteOperationUsages OperationUsage
}

// PermissionRequestData is a struct that holds data concerning the permission request . It includes things like users,roles,groups,operation(constants.OperationCreate|constants.OperationRead....) etc. necessary to help get permission status
type PermissionRequestData struct {
	Operation               string
	UserEntityPermissions   Permission
	RoleEntityPermissions   Permission
	GroupEntityPermissions  Permission
	DomainEntityPermissions Permission
	OrgEntityPermissions    Permission //Organization EntityPermissions
	EntityPermissionOrder   string     // the flow in which the permission should take e.g org->domain->group->role->user //default order is org->
}

// PermissionWithUsageRequestData to hold permission data and also check permission against usage and limits, so if operationQuantity + usage exceeds limit, deny access, but if its less or equal to grant access, hope you get the gist
type PermissionWithUsageRequestData struct {
	PermissionRequestData
	OperationQuantity uint
	UserEntityUsage   PermissionUsage
	RoleEntityUsage   PermissionUsage
	GroupEntityUsage  PermissionUsage
	DomainEntityUsage PermissionUsage
	OrgEntityUsage    PermissionUsage
}

func IsOperationPermitted(permissionRequestData PermissionRequestData) bool {
	operation := permissionRequestData.Operation
	permissionOrder := getEntityPermissionOrder(permissionRequestData.EntityPermissionOrder)
	var permissions Permission

	// only allow CRUDE(Create, Read, Update, Delete,Execute) operations
	if isOperationValid(operation) == false {
		fmt.Println("Invalid operation")
		return false
	}

	// if at this point permissionOrder is empty , it means invalid entities were used
	if len(permissionOrder) < 1 {
		fmt.Println("Entity permission order is invalid")
	}

	if len(permissionOrder) > 0 {
		//loop through the split order and check permission for each entity as arranged in the order
		for i := 0; i < len(permissionOrder); i++ {
			currentEntity := permissionOrder[i]

			permissions = getEntityPermission(currentEntity, permissionRequestData)

			isCurrentEntityOperationPermitted := IsEntityOperationPermitted(operation, permissions)
			if isCurrentEntityOperationPermitted == false {

				return false
			}

			// if all checks passed up till this point , that means permission is granted for this entity , so continue to the next entity,
			// but if the entity we just ran check for is the last entity, then it means permission is granted , else continue to next entity
			if i == len(permissionOrder)-1 {
				// this is the last entity in the order
				// this means all checks in the last entity went well if we got to this point
				return true

			} else {
				// this means current entity checks went well, but we are not in the last entity in the order yet, so let's move to the next entity to check if limits are not exceeded
				continue
			}

		}
	}

	return false
}

//todo [LATER] optimise this function , its looping through the permissions twice

// IsOperationPermittedWithUsage is a function to check if operation is permitted, then it checks the usage following the PermissionRequestData.EntityPermissionOrder
// It loops through each entity in the order and checks permission against request usage + operationQuantity for each OperationLimit
func IsOperationPermittedWithUsage(requestData PermissionWithUsageRequestData) bool {
	operationQuantity := requestData.OperationQuantity
	var operationLimits OperationLimit
	var operationUsage OperationUsage
	var entityPermissions Permission
	var entityUsage PermissionUsage

	permissionOrder := getEntityPermissionOrder(requestData.EntityPermissionOrder)

	// Loop through all the usage according to the entity order
	// compare each operation quantity + usage , if the addition is more than its appropriate limit deny access
	// for example, if I am doing a creating 5 files batch , it loops through all the entity's and the limit, it first checks the "batch" limit, if the limit for "batch" is less or equal to 5 continue,
	// following the order, within that same order, it checks all other limits against the usage, if the usage + operation quantity exceeds the corresponding limit, deny access

	if len(permissionOrder) > 0 {
		for i := 0; i < len(permissionOrder); i++ {
			currentEntity := permissionOrder[i]
			// if any of the entity is invalid at any point decline permission
			if isEntityValid(currentEntity) == false {
				fmt.Printf("Invalid entity : %s", currentEntity)
				return false
			}

			// Get current entity permission
			entityPermissions = getEntityPermission(currentEntity, requestData.PermissionRequestData)
			// first we check current operation is permitted for this entity, before moving to its limits
			isCurrentEntityOperationPermitted := IsEntityOperationPermitted(requestData.Operation, entityPermissions)
			if isCurrentEntityOperationPermitted == false {

				fmt.Printf("%s %s", currentEntity, requestData.Operation)
				fmt.Print(entityPermissions)
				return false
			}
			//todo test scenario and implications of what happens if one of the entity permissions is not set at all, meaning its "empty"
			// I think if it is, it should not be put in the order at all, so by default , if its empty all the limit checks would pass, except the batchLimit, which has to be at least 1
			// SO this would force the users to either set the fields for the entity, or remove it completely from the order

			// Get entity usage
			entityUsage = getEntityPermissionUsage(currentEntity, requestData)
			if requestData.Operation == constants.OperationCreate {
				operationLimits = entityPermissions.CreateOperationLimits
				operationUsage = entityUsage.CreateOperationUsages
			}
			if requestData.Operation == constants.OperationRead {
				operationLimits = entityPermissions.ReadOperationLimits
				operationUsage = entityUsage.ReadOperationUsages
			}
			if requestData.Operation == constants.OperationUpdate {
				operationLimits = entityPermissions.UpdateOperationLimits
				operationUsage = entityUsage.UpdateOperationUsages
			}

			if requestData.Operation == constants.OperationDelete {
				operationLimits = entityPermissions.DeleteOperationLimits
				operationUsage = entityUsage.DeleteOperationUsages
			}

			if requestData.Operation == constants.OperationExecute {
				operationLimits = entityPermissions.ExecuteOperationLimits
				operationUsage = entityUsage.ExecuteOperationUsages
			}
			// Now let's get values of the various fields we need for the current operation we are checking permission for

			// Let's start with limits
			quotaLimit := entityPermissions.QuotaLimit
			allTimeLimit := operationLimits.AllTimeLimit
			batchLimit := operationLimits.getBatchLimit()
			perMinuteLimit := operationLimits.PerMinuteLimit
			perHourLimit := operationLimits.PerHourLimit
			perDayLimit := operationLimits.PerDayLimit
			perWeekLimit := operationLimits.PerWeekLimit
			perFortnightLimit := operationLimits.PerFortnightLimit
			perMonthLimit := operationLimits.PerMonthLimit
			perQuarterLimit := operationLimits.PerQuarterLimit
			perYearLimit := operationLimits.PerYearLimit
			//customDurationsLimit:=operationLimits.CustomDurationsLimit

			// NOTE THIS IS IMPORTANT DON'T REMOVE ELSE YOU MAY HAVE UNEXPECTED BEHAVIOUR - first let's sanitize usage
			operationUsage.sanitizeDurationUsage()
			// Let's get usage values
			quotaUsage := entityUsage.QuotaUsage
			allTimeUsage := operationUsage.AllTime
			usageWithinMinute := operationUsage.WithinTheLastMinute
			usageWithinHour := operationUsage.WithinTheLastHour
			usageWithinDay := operationUsage.WithinTheLastDay
			usageWithinWeek := operationUsage.WithinTheLastWeek
			usageWithinFortnight := operationUsage.WithinTheLastFortnight
			usageWithinMonth := operationUsage.WithinTheLastMonth
			usageWithinQuarter := operationUsage.WithinTheLastQuarter
			usageWithinYear := operationUsage.WithinTheLastYear
			//usageWithinCustomDurations:=operationUsage.WithinTheLastCustomDurations

			// special error message for batch value, because it can't be 0, it needs to be at least 1, this is to protect the user of permitta, forcing them to set a batch limit
			if batchLimit < 1 {
				fmt.Printf("%sOperationLimits.BatchLimit value for %s entity has to be at least 1  \n", firstLetterToUppercase(requestData.Operation), currentEntity)
				return false
			}

			// if any of the limit values is less than 0, deny permission, because that's not normal, I have taken precaution to prevent this, but just in case there is a scenario, I didn't consider that made invalid value slip through
			if quotaLimit < 0 ||
				allTimeLimit < 0 ||
				perMinuteLimit < 0 ||
				perHourLimit < 0 ||
				perDayLimit < 0 ||
				perWeekLimit < 0 ||
				perFortnightLimit < 0 ||
				perMonthLimit < 0 ||
				perQuarterLimit < 0 ||
				perYearLimit < 0 {
				fmt.Printf("Invalid limit value \n Check all your %s entity permission limit values to ensure they are all valid, none of them should be less than 0 \n", currentEntity)
				return false
			}

			if quotaUsage < 0 ||
				allTimeUsage < 0 ||
				usageWithinMinute < 0 ||
				usageWithinHour < 0 ||
				usageWithinDay < 0 ||
				usageWithinWeek < 0 ||
				usageWithinFortnight < 0 ||
				usageWithinMonth < 0 ||
				usageWithinQuarter < 0 ||
				usageWithinYear < 0 {
				fmt.Printf("Invalid usage value \n Check all your %s entity permission usage values to ensure they are all valid, none of them should be less than 0 \n", currentEntity)
				return false
			}

			// TODO Document that batch limit default value is automatically assumed, or enforced as 1, not unlimited, to prevent abuse
			// TODO CONTD - where users try to perform too many operations at once

			// if BatchLimit
			// First check ^BatchLimit is not exceeded , if its exceeded deny permission, there is no need to check the next order
			// Also if fore some reason batchLimit is -1 , this is not a valid value, so deny permission
			// batchLimit is not like other limits where 0 denotes unlimited, this forces any permitta user to set a strict batch limit value
			if operationQuantity > batchLimit {

				fmt.Printf("Batch Limit exceeded for entity:%s and operation:%s \n", currentEntity, requestData.Operation)
				return false
			}

			//Check Quota Limit first , and only check Quota limit, when we are performing a create operation/permission request

			if (requestData.Operation == constants.OperationCreate) && (operationQuantity+quotaUsage > quotaLimit) && (quotaLimit != constants.Unlimited) {

				return false
			}

			// Next let's check all time limit for current entity, and deny access if exceeded
			// to do that , we ensure operation quantity + all time usage doesn't exceed all time limit , and the all-time limit value isn't unlimited =0
			if (operationQuantity+allTimeUsage > allTimeLimit) && allTimeLimit != constants.Unlimited {
				return false
			}

			// next check per minute limit
			if (operationQuantity+usageWithinMinute > perMinuteLimit) && perMinuteLimit != constants.Unlimited {
				return false
			}

			// next check per hour limit
			if (operationQuantity+usageWithinHour > perHourLimit) && perHourLimit != constants.Unlimited {
				return false
			}

			// next check per day limit
			if (operationQuantity+usageWithinDay > perDayLimit) && perDayLimit != constants.Unlimited {
				return false
			}

			// next check per week limit
			if (operationQuantity+usageWithinWeek > perWeekLimit) && perWeekLimit != constants.Unlimited {
				return false
			}

			// next check per fortnight limit
			if (operationQuantity+usageWithinFortnight > perFortnightLimit) && perFortnightLimit != constants.Unlimited {
				return false
			}

			// next check per month limit
			if (operationQuantity+usageWithinMonth > perMonthLimit) && perMonthLimit != constants.Unlimited {
				return false
			}

			// next check per quarter limit
			if (operationQuantity+usageWithinQuarter > perQuarterLimit) && perQuarterLimit != constants.Unlimited {
				return false
			}

			// next check per year limit
			if (operationQuantity+usageWithinYear > perYearLimit) && perYearLimit != constants.Unlimited {
				return false
			}

			// todo come and add custom durations limit check

			// if all checks passed up till this point , that means permission is granted for this entity , so continue to the next entity,
			// but if the entity we just ran check for is the last entity, then it means permission is granted , else continue to next entity
			if i == len(permissionOrder)-1 {
				// this is the last entity in the order
				// this means all checks in the last entity went well if we got to this point
				return true

			} else {
				// this means current entity checks went well, but we are not in the last entity in the order yet, so let's move to the next entity to check if limits are not exceeded
				continue
			}
		}
	}

	return false
}

func IsEntityOperationPermitted(operation string, entityPermissions Permission) bool {
	// ensure the operation is valid
	if isOperationValid(operation) == false {
		return false
	}

	if operation == constants.OperationCreate {
		return entityPermissions.Create
	}

	if operation == constants.OperationRead {
		return entityPermissions.Read
	}

	if operation == constants.OperationUpdate {
		return entityPermissions.Update
	}

	if operation == constants.OperationDelete {
		return entityPermissions.Delete
	}

	if operation == constants.OperationExecute {
		return entityPermissions.Execute
	}

	return false
}

func GetOperationLimits(operation string, permission Permission) OperationLimit {
	if operation == constants.OperationCreate {
		return permission.CreateOperationLimits
	}
	if operation == constants.OperationRead {
		return permission.ReadOperationLimits
	}
	if operation == constants.OperationUpdate {
		return permission.UpdateOperationLimits
	}
	if operation == constants.OperationDelete {
		return permission.DeleteOperationLimits
	}

	if operation == constants.OperationExecute {
		return permission.ExecuteOperationLimits
	}

	return OperationLimit{}
}

func GetOperationUsages(operation string, permissionUsage PermissionUsage) OperationUsage {
	var operationUsage OperationUsage
	if operation == constants.OperationCreate {
		operationUsage = permissionUsage.CreateOperationUsages
	}
	if operation == constants.OperationRead {
		operationUsage = permissionUsage.ReadOperationUsages
	}
	if operation == constants.OperationUpdate {
		operationUsage = permissionUsage.UpdateOperationUsages
	}
	if operation == constants.OperationDelete {
		operationUsage = permissionUsage.DeleteOperationUsages
	}

	if operation == constants.OperationExecute {
		operationUsage = permissionUsage.ExecuteOperationUsages
	}

	// sanitize operationUsage
	operationUsage.sanitizeDurationUsage()

	return operationUsage
}

// GetOperationLimitsHumanFriendly outputs the limits in a map of human friendly format.
// For example, since 0 denotes "unlimited", we want to literally have the limit value as unlimited
func GetOperationLimitsHumanFriendly(operation string, permission Permission) map[string]string {
	thisOperationLimits := GetOperationLimits(operation, permission)

	m := make(map[string]string)
	rv := reflect.ValueOf(thisOperationLimits)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		fieldValue := fmt.Sprintf("%v", field.Interface())
		if fieldValue == fmt.Sprintf("%v", constants.Unlimited) {
			fieldValue = constants.UnlimitedString
		}
		m[rv.Type().Field(i).Name] = fieldValue

	}
	return m

}
func isOperationValid(operation string) bool {
	// ensure the operation is correct
	if operation != constants.OperationCreate &&
		operation != constants.OperationRead &&
		operation != constants.OperationUpdate &&
		operation != constants.OperationDelete &&
		operation != constants.OperationExecute {
		return false
	}

	return true
}

func firstLetterToUppercase(s string) string {
	return strings.ToUpper(string(s[0])) + s[1:]

}

func getEntityPermissionOrder(permissionOrder string) []string {
	var finalOrder []string
	permissionOrder = strings.ReplaceAll(permissionOrder, " ", "")

	// if permission is granted in one entity / order level, go to the next , if all is granted and the loop is at the last point and the last one is granted, grant permission else, deny permission
	//if permissionOrder is empty use default
	//NOTE doc that if the put in empty order, the permission order would be the default
	// If they also put in characters tha is less than the MinimumEntityPermissionOrderLength , the permission order would be the default
	if permissionOrder == "" || len(permissionOrder) < constants.MinimumEntityPermissionOrderLength {
		permissionOrder = constants.DefaultEntityPermissionOrder
	}
	// for scenario where we want to check permission for just one entity and there is no separator , just a single word denoting the entity
	if strings.Contains(permissionOrder, constants.OrderSeparator) == false {
		if isEntityValid(permissionOrder) {
			return []string{permissionOrder}
		}
	}

	// for other scenarios where the separator is included
	if strings.Contains(permissionOrder, constants.OrderSeparator) == true {
		splitOrder := strings.Split(permissionOrder, constants.OrderSeparator)
		if len(splitOrder) > 0 {

			// loop through the orders in the slice and if current entity is valid append it to the final order
			for i := 0; i < len(splitOrder); i++ {

				if isEntityValid(splitOrder[i]) == true {
					finalOrder = append(finalOrder, splitOrder[i])
				}
			}

		}
		return finalOrder
	}

	return []string{}
}

func getEntityPermission(entityName string, permissionRequestData PermissionRequestData) Permission {
	var permissions Permission
	switch entityName {
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

	return permissions
}

func getEntityPermissionUsage(entityName string, usageRequestData PermissionWithUsageRequestData) PermissionUsage {
	var usage PermissionUsage
	switch entityName {
	case constants.EntityOrg:
		usage = usageRequestData.OrgEntityUsage
		break
	case constants.EntityDomain:
		usage = usageRequestData.DomainEntityUsage
		break
	case constants.EntityGroup:
		usage = usageRequestData.GroupEntityUsage
		break
	case constants.EntityRole:
		usage = usageRequestData.RoleEntityUsage
		break
	case constants.EntityUser:
		usage = usageRequestData.UserEntityUsage
		break
	default:
		usage = PermissionUsage{}
		break
	}

	return usage
}

func isEntityValid(entityName string) bool {
	// ensure the operation is correct
	if entityName != constants.EntityOrg &&
		entityName != constants.EntityDomain &&
		entityName != constants.EntityGroup &&
		entityName != constants.EntityRole &&
		entityName != constants.EntityUser {
		return false
	}

	return true
}

func replaceLastOccurrence(s, old, new string) string {
	index := strings.LastIndex(s, old)
	if index == -1 {
		return s
	}
	return s[:index] + new + s[index+len(old):]
}

// sanitizeNotation is a function that "cleans up " notations and remove unnecessary sections , it doesn't validate, it only cleans up
func sanitizeNotation(notation string) string {
	// Clean up space first
	notation = strings.ReplaceAll(notation, " ", "")
	// clean up new line and tab
	notation = strings.ReplaceAll(notation, "\n", "")
	notation = strings.ReplaceAll(notation, "\t", "")

	// if there is any empty section remove that section , to be more specific, if there is any invalid limit section remove it.
	// I know I said we won't do validation here, but we kind of already are
	if strings.Contains(notation, constants.NotationSectionSeparator) == true {
		notationSections := strings.Split(notation, constants.NotationSectionSeparator)
		newNotation := ""
		for i := 0; i < len(notationSections); i++ {
			currentSectionString := notationSections[i]
			//rebuild the notation , only add section if it starts with a valid section prefix
			if strings.HasPrefix(currentSectionString, "c") || //for first section that could be something like "cr-de"
				strings.HasPrefix(currentSectionString, "-") || // for something like "-r---"
				strings.HasPrefix(currentSectionString, "q=") || // for quotaLimit
				strings.HasPrefix(currentSectionString, "c=") || // for limit section
				strings.HasPrefix(currentSectionString, "r=") || // for limit section
				strings.HasPrefix(currentSectionString, "u=") || // for limit section
				strings.HasPrefix(currentSectionString, "d=") || // for limit section
				strings.HasPrefix(currentSectionString, "e=") {

				// for the section to be added, it also needs to meet certain criteria
				// the length of the string has to be at least 5 characters long , e.g "crud-" and "c=all:5" both are 5 or more characters
				// if it's not last index add separator
				// q= quota section could be less than 5 characters long , e.g q=1, so we would add condition for that , for quota, it has to be greater or equal to 3 characters
				if (len([]rune(currentSectionString)) >= 5 && strings.HasPrefix(currentSectionString, "q=") == false) ||
					(strings.HasPrefix(currentSectionString, "q=") && len([]rune(currentSectionString)) >= 3) {
					if i != len(notationSections)-1 {
						newNotation = newNotation + currentSectionString + constants.NotationSectionSeparator
					} else {
						newNotation = newNotation + currentSectionString
					}
				}
			}

		}

		notation = newNotation
	}

	// let's check if we have one section separator, if we do, this means most like we have something like cr-de| , it's ok and preferable to have it just like cr-de without the separator, so let's clean that up
	// it won't be high-tech, if there is one separator, just remove it, especially when it's at the end
	// it needs to be the scenario where it's at the end , because we could have one separator and have something like this cr-de|c=batch:2 in this case, we don't want to remove the section separator
	// But we could also have cr-de|c=batch:2| , so this means, we don't want to check if there is just one separator, we just want to remove the separator if its the last string
	if strings.HasSuffix(notation, constants.NotationSectionSeparator) == true {
		notation = replaceLastOccurrence(notation, constants.NotationSectionSeparator, "")
	}

	return notation
}

//TODO add a way to write this permissions in shorthand , both for obscurity and quick writing of permissions
// Then write a function to intepreter that shorthand, its basically just parsing using strings.split , you might even create your own standard of writing permissions and propose it to a body tasked with standardizing things like this
// FOllowing the unix permission pattern for each entity, you can do , "crud-","c"{all:0,batch:1,minute:0,hour:5,day:0,week:45,fortnight:0,monthly:0,quarterly:0,yearly:0,customDurations:[per_5_minutes_4,per_3_days_50]|r:....

// NotationToPermission converts a notation string to a permission "object"/struct. Its just a useful "shorthand" way to write permissions without using the struct directly
//
// Below is an example of what a notation looks like . Read in the repo documentation for details
//
// q=30 standards for QuotaLimit of 30
//
//	crud-|q=30|c=month:0,day:100,batch:1,minute:5,hour:20,week:500,fortnight:700,year:10000,quarter:5000,custom:[per_5_minutes_4 & per_3_days_50]|r=..
func NotationToPermission(notation string) Permission {
	var finalPermission Permission
	// just in case there is space in the string, let's trim space, but there shouldn't be space
	notation = sanitizeNotation(notation)
	includeThisOperationLimit := false
	var currentLimitSection string
	var notationSections []string
	var operationPermissionSection string //for the first section like cr-de
	// first let's split the notation into its different section
	if strings.Contains(notation, constants.NotationSectionSeparator) {

		notationSections = strings.Split(notation, constants.NotationSectionSeparator)
		operationPermissionSection = notationSections[0]
		// There should always be at most 6 sections , and at least one section e.g. cr-de| this implies create, read, delete, execute is allowed and all its limits are unlimited, except batch limits which is set to 1 by default
		if len(notationSections) < 1 || len(notationSections) > 6 {
			fmt.Println("Malformed permission notation")
			return Permission{}
		}
	} else {
		// the notation doesn't contain the separator, so we assume it's just the operationPermissionSection without the limits section
		operationPermissionSection = notation
	}

	// if we got here, it means the notation is properly formed so far
	// let's check the first section if its properly formed, if it is we can proceed,
	// it should always be 5 characters long , because it should be like "crude" , which stands for CREATE, READ, UPDATE, DELETE, EXECUTE . , if we don't want to grant permission to any of these operations any of the letters in "crude" can be replaced with a minus sign "-"
	// But the letter have to ALWAYS follow that order, or be replaced by "-"
	// so let's use regex
	firstSectionPattern := regexp.MustCompile(`^([c-][r-][u-][d-][e-])$`)
	if firstSectionPattern.MatchString(operationPermissionSection) == false {
		fmt.Println("Malformed permission notation")
		return Permission{}
	}

	// if we got here it means the pattern matched, and we are good to set the permission values for the operations
	for i, operationPermissionInit := range operationPermissionSection {

		if i == 0 {
			if string(operationPermissionInit) == "c" {
				finalPermission.Create = true
				// set default limits

			}
		}

		if i == 1 {
			if string(operationPermissionInit) == "r" {
				finalPermission.Read = true

			}
		}

		if i == 2 {
			if string(operationPermissionInit) == "u" {
				finalPermission.Update = true

			}
		}

		if i == 3 {
			if string(operationPermissionInit) == "d" {
				finalPermission.Delete = true

			}
		}

		if i == 4 {
			if string(operationPermissionInit) == "e" {
				finalPermission.Execute = true
			}
		}

	}

	//NOTE document this :

	// Let's move to the remaining sections, we can just loop through them , since they have similar syntax
	// NOTE The remaining sections don't have to be set if I want to let all the limits be unlimited and the batch limit to be 1
	// the remaining sections is for limits , create limits for example would be defined like :
	// c=month:0,day:100,batch:1,minute:5,hour:20,week:500,fortnight:700,year:10000,quarter:5000,custom:[per_5_minutes_4,per_3_days_50]
	// one of the limits section can be the quota limit q=int , if its not set , it assumes quota is unlimited
	// for other operations "c=" can just be replaced with "r=" or "u=" or "d=" or "e="
	// Just like the operation permission section similarly the proceeding sections should also follow an order
	// e.g c-ude|q=5|c=....|r=...|u=...|d=...|e=...
	// Its required that in each operation limit section, at least the batch limit should be set (else its pegged at 1 by default)
	// The individual limits within each operation limit section can be arranged in any order
	// If any limit is excluded, its assumed that the value is unlimited , batch limit can never be unlimited, this is why if its not set, it automatically enforced as 1, where corresponding operation permission is granted
	// Let's start the loop , we would be starting the loop from index 1, since index 0 is the operation permissions which we have already handled
	// Operation Limit sections can be left empty even if the said operation is granted permission, this would imply that batch limit is the default of 1 and all other limits are unlimited
	// for example if you have crud-| implies create, read, update and delete permission is granted, and all its limits are unlimited and all its batch limit is set to 1
	// only run this loop if limits are set this means the notationSections is greater than 1

	if len(notationSections) > 1 {

		for i := 1; i < len(notationSections); i++ {
			//reset include operation limit
			includeThisOperationLimit = false
			currentLimitSection = ""
			// Let's check if current section is properly formed, this isn't a perfect test for a properly formed operation limit section , but it would do for now
			// todo improve this

			// if its Quota Limit section
			if strings.HasPrefix(notationSections[i], "q=") == true {
				// Quota section split
				quotaSectionSplit := strings.Split(notationSections[i], "=")
				quotaValue, quotaValueErr := stringToPositiveIntegerOrZero(quotaSectionSplit[1])
				if quotaValueErr != nil {
					fmt.Println("Malformed quota limit in notation")
					finalPermission = Permission{}
					return finalPermission
				} else {
					finalPermission.QuotaLimit = quotaValue
				}

			}
			if strings.HasPrefix(notationSections[i], "c=") == true && finalPermission.Create == true {
				includeThisOperationLimit = true
				currentLimitSection = constants.OperationCreate

			}

			if strings.HasPrefix(notationSections[i], "r=") == true && finalPermission.Read == true {
				includeThisOperationLimit = true
				currentLimitSection = constants.OperationRead

			}

			if strings.HasPrefix(notationSections[i], "u=") == true && finalPermission.Update == true {
				includeThisOperationLimit = true
				currentLimitSection = constants.OperationUpdate

			}

			if strings.HasPrefix(notationSections[i], "d=") == true && finalPermission.Delete == true {
				includeThisOperationLimit = true
				currentLimitSection = constants.OperationDelete

			}

			if strings.HasPrefix(notationSections[i], "e=") == true && finalPermission.Execute == true {
				includeThisOperationLimit = true
				currentLimitSection = constants.OperationExecute

			}

			if includeThisOperationLimit == true {
				//split and loop through the current operation limit to add
				// first split the operation key from the limit list
				splitOperationLimitSection := strings.Split(notationSections[i], "=")
				// now let's split the limits itself , and assign the limits where they are available, and return the new updated limits
				operationLimit, operationLimitErr := getNotationOperationLimits(splitOperationLimitSection[1]) //todo handle error here
				// if for any reason there is an error getting operation limit, its very important to set original operation permission to false, else there would be a loop hole, where, users can be granted unlimited access, so set final permission to empty
				if operationLimitErr != nil {
					finalPermission = Permission{}
					return finalPermission
				}
				switch currentLimitSection {
				// for scenarios where
				case constants.OperationCreate:

					finalPermission.CreateOperationLimits = operationLimit

					break
				case constants.OperationRead:
					finalPermission.ReadOperationLimits = operationLimit

					break
				case constants.OperationUpdate:
					finalPermission.UpdateOperationLimits = operationLimit

					break
				case constants.OperationDelete:
					finalPermission.DeleteOperationLimits = operationLimit
					break
				case constants.OperationExecute:
					finalPermission.ExecuteOperationLimits = operationLimit
					break

				}

			}

		}
	}

	// set default limits for granted permissions in case they were not set
	//todo improve this
	if finalPermission.Create == true {
		finalPermission.CreateOperationLimits.setDefaultLimits()
	}

	if finalPermission.Read == true {
		finalPermission.ReadOperationLimits.setDefaultLimits()

	}

	if finalPermission.Update == true {
		finalPermission.UpdateOperationLimits.setDefaultLimits()

	}

	if finalPermission.Delete == true {

		finalPermission.DeleteOperationLimits.setDefaultLimits()
	}

	if finalPermission.Execute == true {
		finalPermission.ExecuteOperationLimits.setDefaultLimits()
	}
	return finalPermission

}

// getNotationOperationLimitAndValue receives limit data like "week:5" or "batch:3"
func getNotationOperationLimitAndValue(limitData string) (string, uint, bool) {

	limitData = strings.ReplaceAll(limitData, " ", "")
	// let's check if the limit data is properly formed
	// if it doesn't contain the string that separates limitType from value, then its not valid
	// let's use regex for this
	//  pattern ensures that the right pattern is followed limit:uint
	// however, it forces batch , to be >=1 to be valid , all other limits can be 0 to denote unlimited
	regexPattern := `^(batch:[1-9]\d*)$|(all|minute|hour|day|week|fortnight|month|quarter|year)(:\d+)$`
	regex := regexp.MustCompile(regexPattern)
	if regex.MatchString(limitData) == false {
		return "", 0, false
	}
	// split the limit data since we have verified that its valid
	splitLimitData := strings.Split(limitData, constants.NotationOperationLimitAndValueSeparator)
	limitType := splitLimitData[0]
	limitValue := splitLimitData[1]

	// Best regex so far for the custom limit
	//	custom:\[(?:per_\d+_?[a-z]+_\d+(?:&|$))+\]

	// Da accurate one !!! ANd I did it myself, AI did the one above, I was closer than AI
	//	^(custom:\[)((per_\d+_[a-z]+_\d+\&)+|(per_\d+_[a-z]+_\d+){1})+(\])$
	// This one adds option for the custom limit to be empty
	//	^(custom:\[)((per_\d+_[a-z]+_\d+\&)+|(per_\d+_[a-z]+_\d+){1})+(\])$|custom:\[\]$
	// Even improved more
	// ^custom:\[((per_\d+_[a-z]+_\d+\&)+|(per_\d+_[a-z]+_\d+){1})+\]$|^custom:\[\]$

	// The regexes above allow 0 value after per_ we should have per_0_minutes_10 for example, it should be at least per_1
	//Improved AND TESTED
	//	^custom:\[((per_[1-9]\d*_[a-z]+_\d+\&)+|(per_[1-9]\d*_[a-z]+_\d+){1})+\]$|^custom:\[\]$

	//todo create tool where you can write regex and see the syntax clearly , like breaking new line, like in a nested if statement, or even a if statement kind of flow

	limitValueUintInit, limitValueErr := strconv.ParseUint(limitValue, 10, 64)
	if limitValueErr != nil {
		// conversion/parsing was not successful
		return "", 0, false
	}
	// if we get to this point it means conversion was successful
	limitValueUint := uint(limitValueUintInit)

	// if we got to this point , regex has validated the limitData to be correct
	// we also successfully converted the limitValue to uint
	return limitType, limitValueUint, true

}

// getNotationOperationCustomLimitValue receives limit data like "custom:[per_5_minutes_10&per_2_month_90]"
func getNotationOperationCustomLimitValue(limitData string) ([]string, bool) {
	var customLimitList []string

	regexPattern := `^custom:\[((per_[1-9]\d*_[a-z]+_\d+\&)+|(per_[1-9]\d*_[a-z]+_\d+){1})+\]$|^custom:\[\]$`
	regex := regexp.MustCompile(regexPattern)
	if regex.MatchString(limitData) == false {
		return []string{}, false
	}
	// split the limit data since we have verified that its valid
	splitLimitData := strings.Split(limitData, constants.NotationOperationLimitAndValueSeparator)
	//limitType :=splitLimitData[0]
	limitValue := splitLimitData[1]

	// remove the value prefix and suffix to denote a list
	limitValue = strings.ReplaceAll(limitValue, constants.NotationCustomLimitValuePrefix, "")
	limitValue = strings.ReplaceAll(limitValue, constants.NotationCustomLimitValueSuffix, "")
	// check if it contains separator
	if strings.Contains(limitValue, constants.NotationCustomLimitValueListSeparator) == false {
		// Since its false , most likely, we have just one custom limit, so lets, just push it
		//todo comeback when you have written validator for the main OperationLimit.CustomDurationsLimit, use the same validator here, since the syntax for the full custom and notation custom limts are the same
		customLimitList = append(customLimitList, limitValue)
	}

	if strings.Contains(limitValue, constants.NotationCustomLimitValueListSeparator) == true {
		// Since it's true, we potentially have at least two custom limits in the list, so let's split and iterate
		splitCustomLimits := strings.Split(limitValue, constants.NotationCustomLimitValueListSeparator)
		if len(splitCustomLimits) > 0 {
			for i := 0; i < len(splitCustomLimits); i++ {
				currentCustomLimit := splitCustomLimits[i]
				//todo validate value here, regex has already validated the structure, but we need to validate
				customLimitList = append(customLimitList, currentCustomLimit)
			}
		}
		//todo comeback when you have written validator for the main OperationLimit.CustomDurationsLimit, use the same validator here, since the syntax for the full custom and notation custom limts are the same
		customLimitList = append(customLimitList, limitValue)
	}

	return customLimitList, true

}

func getCustomLimitsNotationValues(customLimitValue string) []string {
	// if it doesn't start with "[" or does not end with "]" its invalid
	if strings.HasPrefix(customLimitValue, constants.NotationCustomLimitValuePrefix) == false || strings.HasSuffix(customLimitValue, constants.NotationCustomLimitValueSuffix) == false {
		return []string{}
	}
	// if we got here its formed properly so far.
	// let's see if it contains at list one list separator , if it doesn't we assume
	//todo come and finish custom limit

	return []string{}
}

func getNotationOperationLimits(operationLimitsString string) (OperationLimit, error) {
	var currentOperationLimit OperationLimit

	//trim spaces
	operationLimitsString = strings.ReplaceAll(operationLimitsString, " ", "")
	// for scenario where there is just for one limit and there is no separator , just potentially one limit, which has to by design be required to be the batch limit
	if strings.Contains(operationLimitsString, constants.NotationOperationLimitsSeparator) == false {
		// now we check the string if it at least has the format limit:value e.g batch:3,
		// so it has to at least contain ":", and then when split , should be at least a len of 2
		// we also need to make sure that we don't have more than one ":", this is to ensure that users always separate the limits with comma
		if strings.Contains(operationLimitsString, constants.NotationOperationLimitAndValueSeparator) == true && strings.Count(operationLimitsString, constants.NotationOperationLimitAndValueSeparator) == 1 {

			splitSingleLimit := strings.Split(operationLimitsString, constants.NotationOperationLimitAndValueSeparator)
			// the len has to be at exactly 2, else it's not valid
			if len(splitSingleLimit) == 2 {
				// Now that we are here, if we have gotten to this point it means there is only one valid limit for this operation Limit,
				// add a  comma to the end of the operationLimitsString , to ensure that the split below defined in splitLimits works, since this currently appears to be a likely valid limit
				operationLimitsString = operationLimitsString + constants.NotationOperationLimitsSeparator
			}
		} else {
			fmt.Println("malformed notation operation limits, check that its properly formed, and has the required limits")
			return currentOperationLimit, fmt.Errorf("malformed notation operation limits, check that its properly formed, and has the required limits")
		}

	}

	// for other scenarios where the separator is included, possibly indicating multiple limits
	if strings.Contains(operationLimitsString, constants.NotationOperationLimitsSeparator) == true {
		splitLimits := strings.Split(operationLimitsString, constants.NotationOperationLimitsSeparator)
		if len(splitLimits) > 0 {

			// loop through the limits in the slice
			// if any of the limits or its value is invalid, return error
			for i := 0; i < len(splitLimits); i++ {
				currentLimitData := splitLimits[i]
				//ensure the length of the limit data is not less than 5 chars , e.g all:5 is valid because its 5 characters
				if len([]rune(currentLimitData)) >= 5 {
					// check if current limit data contains the right seprator is
					// if its not custom limit
					if strings.Contains(currentLimitData, constants.NotationOperationCustomLimitKey) == true {
						customLimitSlice, isCustomLimitValid := getNotationOperationCustomLimitValue(currentLimitData)
						if isCustomLimitValid {
							currentOperationLimit.CustomDurationsLimit = customLimitSlice
						} else {
							fmt.Println("malformed notation operation limits, check that the custom limits are properly formed")
						}
					} else {
						// for other limits
						currentLimitType, currentLimitValue, isCurrentLimitDataValid := getNotationOperationLimitAndValue(currentLimitData)

						if isCurrentLimitDataValid == true { // set batch limit
							if currentLimitType == constants.NotationOperationBatchLimitKey {
								currentOperationLimit.BatchLimit = currentLimitValue
								currentOperationLimit.BatchLimit = currentOperationLimit.getBatchLimit() //forces the default limit to be 1 , if this value is 0, because batch limit can't be 0
							}

							// set all time limit
							if currentLimitType == constants.NotationOperationAllTimeLimitKey {
								currentOperationLimit.AllTimeLimit = currentLimitValue
							}
							// set all minute limit
							if currentLimitType == constants.NotationOperationMinuteLimitKey {
								currentOperationLimit.PerMinuteLimit = currentLimitValue
							}
							// set all hour limit
							if currentLimitType == constants.NotationOperationHourLimitKey {
								currentOperationLimit.PerHourLimit = currentLimitValue
							}
							// set all day limit
							if currentLimitType == constants.NotationOperationDayLimitKey {
								currentOperationLimit.PerDayLimit = currentLimitValue
							}
							// set all week limit
							if currentLimitType == constants.NotationOperationWeekLimitKey {
								currentOperationLimit.PerWeekLimit = currentLimitValue
							}

							// set all fortnight limit
							if currentLimitType == constants.NotationOperationFortnightLimitKey {
								currentOperationLimit.PerFortnightLimit = currentLimitValue
							}

							// set all month limit
							if currentLimitType == constants.NotationOperationMonthLimitKey {
								currentOperationLimit.PerMonthLimit = currentLimitValue
							}

							// set all quarter limit
							if currentLimitType == constants.NotationOperationQuarterLimitKey {
								currentOperationLimit.PerQuarterLimit = currentLimitValue
							}

							// set all year limit
							if currentLimitType == constants.NotationOperationYearLimitKey {
								currentOperationLimit.PerYearLimit = currentLimitValue
							}
						} else {
							// unknown limit, so return error
							fmt.Printf("malformed notation operation limits, '%s' \n", currentLimitData)
							return currentOperationLimit, fmt.Errorf("malformed notation operation limits, '%s' \n", currentLimitData)
						}

					}
				}
			}

		}
		return currentOperationLimit, nil
	}

	return currentOperationLimit, fmt.Errorf("unknown error") //todo come back and improve this error message

}

// RequestMethodToOperation receives a valid HTTP request method and converts it to an operation, using the standard REST conventions of :
//
// POST => create , GET => read , PUT => update , DELETE => delete ,
// todo add "execute operation"
func RequestMethodToOperation(method string) string {
	method = strings.ToUpper(method)
	if method == "POST" {
		return constants.OperationCreate
	}
	if method == "GET" {
		return constants.OperationRead
	}
	if method == "PUT" {
		return constants.OperationUpdate
	}

	if method == "DELETE" {
		return constants.OperationDelete
	}

	return ""
}

func stringToPositiveIntegerOrZero(s string) (uint, error) {
	//remove all spaces
	s = removeAllWhiteSpaces(s)
	// Check if the string is empty
	if len(s) == 0 {
		return 0, errors.New("string is empty")
	}

	// Try to convert the string to a uint
	i, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid integer: %w", err)
	}

	return uint(i), nil
}

func removeAllWhiteSpaces(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

type UpdateUsageData struct {
	DoNotReduceQuotaUsageOnDelete bool
	Operation                     string
	OperationQuantity             uint
	OperationTime                 time.Time
}

func UpdateUsage(updateUsageData UpdateUsageData, usage PermissionUsage) PermissionUsage {
	var operationUsage OperationUsage

	// for create operation
	if updateUsageData.Operation == constants.OperationCreate {
		operationUsage = usage.CreateOperationUsages
		//increase quota usage by one since we are creating a "resource"
		usage.QuotaUsage = usage.QuotaUsage + updateUsageData.OperationQuantity
	}

	if updateUsageData.Operation == constants.OperationRead {
		operationUsage = usage.ReadOperationUsages
	}

	if updateUsageData.Operation == constants.OperationUpdate {
		operationUsage = usage.UpdateOperationUsages
	}

	if updateUsageData.Operation == constants.OperationDelete {
		operationUsage = usage.DeleteOperationUsages
		// let's reduce the QuotaUsage by operationQuantity since the Quota has reduced as a result of delete
		quotaUsageAfterDelete := usage.QuotaUsage - updateUsageData.OperationQuantity
		// let's ensure it's not less than 0 , if it is assign 0
		// normally, this shouldn't happen, but if for some reason it does, set it at 0
		if quotaUsageAfterDelete < 0 {
			quotaUsageAfterDelete = 0
		}
		usage.QuotaUsage = quotaUsageAfterDelete
	}

	if updateUsageData.Operation == constants.OperationExecute {
		operationUsage = usage.ExecuteOperationUsages
	}

	//Let's reduce all the operation usage where necessary if duration has passed from the LastTime
	// What does this mean? for example, if the lastTime we updated a file was 2:55pm and the current time is 3:56pm , this means 1 hour and 1 minute has passed .
	// This means more than an hour and minute has passed, so we need to reset OperationUsage.WithinTheLastMinute and OperationUsage.WithinTheLastHour and set those values to current operationQuantity value
	// But if the current time is 3:01 pm , this means  6 minutes has passed and we only need to reset WithinTheLastMinute and increment every other duration limit including WithinTheLastHour
	// todo remember to do same for custom duration, leaving it put for now because its a bit more complex

	// let's first update firstTime if this is the first time we are updating the usage
	if operationUsage.FirstTime.IsZero() {
		operationUsage.FirstTime = updateUsageData.OperationTime
	}

	durationFromLastTime := updateUsageData.OperationTime.Sub(operationUsage.LastTime)

	// update last quantity
	operationUsage.LastQuantity = updateUsageData.OperationQuantity

	// update all time
	operationUsage.AllTime = operationUsage.AllTime + updateUsageData.OperationQuantity

	// update within the last minute
	// if duration from last time is less than or equal to a minute, add the operation quantity
	if durationFromLastTime <= time.Minute {
		operationUsage.WithinTheLastMinute = operationUsage.WithinTheLastMinute + updateUsageData.OperationQuantity
	}
	// if it's greater than reset and set it to current operation quantity
	if durationFromLastTime > time.Minute {
		operationUsage.WithinTheLastMinute = updateUsageData.OperationQuantity
	}

	// update within the last hour
	// if duration from last time is less than or equal to an hour, add the operation quantity
	if durationFromLastTime <= time.Hour {
		operationUsage.WithinTheLastHour = operationUsage.WithinTheLastHour + updateUsageData.OperationQuantity
	}
	// if it's greater than, reset and set it to current operation quantity
	if durationFromLastTime > time.Hour {
		operationUsage.WithinTheLastHour = updateUsageData.OperationQuantity
	}

	// update within the last day
	// if duration from last time is less than or equal to a day, add the operation quantity
	// we have 24 hours in a day. so multiply 24 by an hour
	if durationFromLastTime <= constants.TimeDurationDay {
		operationUsage.WithinTheLastDay = operationUsage.WithinTheLastDay + updateUsageData.OperationQuantity
	}
	// if it's greater than, reset and set it to current operation quantity
	if durationFromLastTime > constants.TimeDurationDay {
		operationUsage.WithinTheLastDay = updateUsageData.OperationQuantity
	}

	// update within the last week
	// if duration from last time is less than or equal to a week, add the operation quantity
	// we have 7 days in a week. so multiply 7 by a day
	if durationFromLastTime <= constants.TimeDurationWeek {
		operationUsage.WithinTheLastWeek = operationUsage.WithinTheLastWeek + updateUsageData.OperationQuantity
	}
	// if it's greater than, reset and set it to current operation quantity
	if durationFromLastTime > constants.TimeDurationWeek {
		operationUsage.WithinTheLastWeek = updateUsageData.OperationQuantity
	}

	// update within the last fortnight
	// if duration from last time is less than or equal to a fortnight, add the operation quantity
	// we have 14 days in a fortnight. so multiply 14 by a day
	if durationFromLastTime <= constants.TimeDurationFortnight {
		operationUsage.WithinTheLastFortnight = operationUsage.WithinTheLastFortnight + updateUsageData.OperationQuantity
	}
	// if it's greater than, reset and set it to current operation quantity
	if durationFromLastTime > constants.TimeDurationFortnight {
		operationUsage.WithinTheLastFortnight = updateUsageData.OperationQuantity
	}

	// update within the last month
	// if duration from last time is less than or equal to a month, add the operation quantity
	// we have 30 days in a month. so multiply 30 by a day
	if durationFromLastTime <= constants.TimeDurationMonth {
		operationUsage.WithinTheLastMonth = operationUsage.WithinTheLastMonth + updateUsageData.OperationQuantity
	}
	// if it's greater than, reset and set it to current operation quantity
	if durationFromLastTime > constants.TimeDurationMonth {
		operationUsage.WithinTheLastMonth = updateUsageData.OperationQuantity
	}

	// update within the last quarter
	// if duration from last time is less than or equal to a quarter, add the operation quantity
	// we have 90 days in a quarter. so multiply 90 by a day
	if durationFromLastTime <= constants.TimeDurationQuarter {
		operationUsage.WithinTheLastQuarter = operationUsage.WithinTheLastQuarter + updateUsageData.OperationQuantity
	}
	// if it's greater than, reset and set it to current operation quantity
	if durationFromLastTime > constants.TimeDurationQuarter {
		operationUsage.WithinTheLastQuarter = updateUsageData.OperationQuantity
	}

	// update within the last year
	// if duration from last time is less than or equal to a year, add the operation quantity
	// we have 360 days in a year. so multiply 360 by a day
	if durationFromLastTime <= constants.TimeDurationYear {
		operationUsage.WithinTheLastYear = operationUsage.WithinTheLastYear + updateUsageData.OperationQuantity
	}
	// if it's greater than, reset and set it to current operation quantity
	if durationFromLastTime > constants.TimeDurationYear {
		operationUsage.WithinTheLastYear = updateUsageData.OperationQuantity
	}

	// todo custom durations

	// update lastTime always
	operationUsage.LastTime = updateUsageData.OperationTime

	switch updateUsageData.Operation {
	case constants.OperationCreate:
		usage.CreateOperationUsages = operationUsage
		break
	case constants.OperationRead:
		usage.ReadOperationUsages = operationUsage
		break
	case constants.OperationUpdate:
		usage.UpdateOperationUsages = operationUsage
		break
	case constants.OperationDelete:
		usage.DeleteOperationUsages = operationUsage
		break
	case constants.OperationExecute:
		usage.ExecuteOperationUsages = operationUsage
		break
	}
	return usage

}
