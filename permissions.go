package permitta

import (
	"fmt"
	constants "gitlab.com/launchbeaver/permitta/constants"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TODO create dart client of this , when its recieving permissions in json
// todo permission check order allowed or not by CRUDE - > not allowed by user->not allowed by role -> not allowed by group -> allowed by user-> allowed by role -> allowed by group -> then  time based limits starting with Batch

// Permission is a very important struct that can be used as an embedded struct to control permissions for just about anything or used as a type, of a struct field
type Permission struct {
	Create  bool `json:"create"`
	Read    bool `json:"read"`
	Update  bool `json:"update"`
	Delete  bool `json:"delete"`
	Execute bool `json:"execute"`

	CreateActionLimits  ActionLimit `json:"createActionLimits"`
	ReadActionLimits    ActionLimit `json:"readActionLimits"`
	UpdateActionLimits  ActionLimit `json:"updateActionLimits"`
	DeleteActionLimits  ActionLimit `json:"deleteActionLimits"`
	ExecuteActionLimits ActionLimit `json:"executeActionLimits"`
}

type ActionLimit struct {
	BatchLimit           uint     `json:"batchLimit"`   // Can be used to limit how many of an item can be deleted at once, or at a time, for example limiting a user to adding 5 files at once . If this value is 5, the user won't be able to delete more than 5 items at once
	AllTimeLimit         uint     `json:"allTimeLimit"` // Can be used to control how many of an item can be stored . For example the total file size you can have stored at any time is 5GB , not to be confused with DeleteLimitBatch
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

type ActionUsage struct {
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

type PermissionUsage struct {
	CreateActionUsages  ActionUsage
	ReadActionUsages    ActionUsage
	UpdateActionUsages  ActionUsage
	DeleteActionUsages  ActionUsage
	ExecuteActionUsages ActionUsage
}

// PermissionRequestData is a struct that holds data concerning the permission request . It includes things like users,roles,groups,actionType(constants.ActionTypeCreate|constants.ActionTypeRead....) etc. necessary to help get permission status
type PermissionRequestData struct {
	ActionType              string
	UserEntityPermissions   Permission
	RoleEntityPermissions   Permission
	GroupEntityPermissions  Permission
	DomainEntityPermissions Permission
	OrgEntityPermissions    Permission //Organization EntityPermissions
	EntityPermissionOrder   string     // the flow in which the permission should take e.g org->domain->group->role->user //default order is org->
}

// PermissionWithUsageRequestData to hold permission data and also check permission against usage and limits, so if actionQuantity + usage exceeds limit, deny access, but if its less or equal to grant access, hope you get the gist
type PermissionWithUsageRequestData struct {
	PermissionRequestData
	ActionQuantity    uint
	UserEntityUsage   PermissionUsage
	RoleEntityUsage   PermissionUsage
	GroupEntityUsage  PermissionUsage
	DomainEntityUsage PermissionUsage
	OrgEntityUsage    PermissionUsage
}

func IsActionPermitted(permissionRequestData PermissionRequestData) bool {
	actionType := permissionRequestData.ActionType
	permissionOrder := getEntityPermissionOrder(permissionRequestData.EntityPermissionOrder)
	var permissions Permission

	// only allow CRUDE(Create, Read, Update, Delete,Execute) action types
	if isActionTypeValid(actionType) == false {
		fmt.Println("Invalid action type")
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

			isCurrentEntityActionPermitted := IsEntityActionPermitted(actionType, permissions)
			if isCurrentEntityActionPermitted == false {

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

// IsActionPermittedWithUsage is a function to check if action is permitted, then it checks the usage following the PermissionRequestData.EntityPermissionOrder
// It loops through each entity in the order and checks permission against request usage + actionQuantity for each ActionLimit
func IsActionPermittedWithUsage(requestData PermissionWithUsageRequestData) bool {
	actionQuantity := requestData.ActionQuantity
	var actionLimits ActionLimit
	var actionUsage ActionUsage
	var entityPermissions Permission
	var entityUsage PermissionUsage

	permissionOrder := getEntityPermissionOrder(requestData.EntityPermissionOrder)

	// Loop through all the usage according to the entity order
	// compare each action quantity + usage , if the addition is more than its appropriate limit deny access
	// for example, if I am doing a creating 5 files batch , it loops through all the entity's and the limit, it first checks the "batch" limit, if the limit for "batch" is less or equal to 5 continue,
	// following the order, within that same order, it checks all other limits against the usage, if the usage + action quantity exceeds the corresponding limit, deny access

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
			// first we check current action is permitted for this entity, before moving to its limits
			isCurrentEntityActionPermitted := IsEntityActionPermitted(requestData.ActionType, entityPermissions)
			if isCurrentEntityActionPermitted == false {

				fmt.Printf("%s %s", currentEntity, requestData.ActionType)
				fmt.Print(entityPermissions)
				return false
			}
			//todo test scenario and implications of what happens if one of the entity permissions is not set at all, meaning its "empty"
			// I think if it is, it should not be put in the order at all, so by default , if its empty all the limit checks would pass, except the batchLimit, which has to be at least 1
			// SO this would force the users to either set the fields for the entoty, or remove it completely from the order

			// Get entity usage
			entityUsage = getEntityPermissionUsage(currentEntity, requestData)
			if requestData.ActionType == constants.ActionTypeCreate {
				actionLimits = entityPermissions.CreateActionLimits
				actionUsage = entityUsage.CreateActionUsages
			}
			if requestData.ActionType == constants.ActionTypeRead {
				actionLimits = entityPermissions.ReadActionLimits
				actionUsage = entityUsage.ReadActionUsages
			}
			if requestData.ActionType == constants.ActionTypeUpdate {
				actionLimits = entityPermissions.UpdateActionLimits
				actionUsage = entityUsage.UpdateActionUsages
			}

			if requestData.ActionType == constants.ActionTypeDelete {
				actionLimits = entityPermissions.DeleteActionLimits
				actionUsage = entityUsage.DeleteActionUsages
			}

			if requestData.ActionType == constants.ActionTypeExecute {
				actionLimits = entityPermissions.ExecuteActionLimits
				actionUsage = entityUsage.ExecuteActionUsages
			}
			// Now let's get values of the various fields we need for the current action we are checking permission for

			// Let's start with limits
			allTimeLimit := actionLimits.AllTimeLimit
			batchLimit := actionLimits.BatchLimit
			perMinuteLimit := actionLimits.PerMinuteLimit
			perHourLimit := actionLimits.PerHourLimit
			perDayLimit := actionLimits.PerDayLimit
			perWeekLimit := actionLimits.PerWeekLimit
			perFortnightLimit := actionLimits.PerFortnightLimit
			perMonthLimit := actionLimits.PerMonthLimit
			perQuarterLimit := actionLimits.PerQuarterLimit
			perYearLimit := actionLimits.PerYearLimit
			//customDurationsLimit:=actionLimits.CustomDurationsLimit

			// Let's get usage values

			allTimeUsage := actionUsage.AllTime
			usageWithinMinute := actionUsage.WithinTheLastMinute
			usageWithinHour := actionUsage.WithinTheLastHour
			usageWithinDay := actionUsage.WithinTheLastDay
			usageWithinWeek := actionUsage.WithinTheLastWeek
			usageWithinFortnight := actionUsage.WithinTheLastFortnight
			usageWithinMonth := actionUsage.WithinTheLastMonth
			usageWithinQuarter := actionUsage.WithinTheLastQuarter
			usageWithinYear := actionUsage.WithinTheLastYear
			//usageWithinCustomDurations:=actionUsage.WithinTheLastCustomDurations

			// special error message for batch value, because it can't be 0, it needs to be at least 1, this is to protect the user of permitta, forcing them to set a batch limit
			if batchLimit < 1 {
				fmt.Printf("%sActionLimits.BatchLimit value for %s entity has to be at least 1  \n", firstLetterToUppercase(requestData.ActionType), currentEntity)
				return false
			}
			// if any of the limit values is less than 0, deny permission, because that's not normal, I have taken precaution to prevent this, but just in case there is a scenario, I didn't consider that made invalid value slip through
			if allTimeLimit < 0 ||
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

			if allTimeUsage < 0 ||
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

			// TODO Document that batch limit is a compulsory field to fill, its slightly different from every other limit  where 0  denotes unlimited . If batch limit for any action is left at the default struct field of 0 the permission request would FAIL, the whole point is to protect anyone who uses permitta from a spamming, where
			// TODO CONTD - where users try to perform too many actions at once

			// if limitBatchB
			// First check ^LimitBatch is not exceeded , if its exceeded deny permission, there is no need to check the next order
			// Also if fore some reason batchLimit is -1 , this is not a valid value, so deny permission
			// batchLimit is not like other limits where 0 denotes unlimited, this forces any permitta user to set a strict batch limit value
			if actionQuantity > batchLimit {
				fmt.Println("doooo")
				fmt.Printf("%s %s", currentEntity, requestData.ActionType)
				fmt.Print(entityPermissions)
				return false
			}

			// Next let's check all time limit for current entity, and deny access if exceeded
			// to do that , we ensure action quantity + all time usage doesn't exceed all time limit , and the all-time limit value isn't unlimited =0
			if (actionQuantity+allTimeUsage > allTimeLimit) && allTimeLimit != constants.Unlimited {
				fmt.Println("pooo")
				fmt.Printf("%s %s", currentEntity, requestData.ActionType)
				fmt.Print(entityPermissions)
				return false
			}

			// next check per minute limit
			if (actionQuantity+usageWithinMinute > perMinuteLimit) && perMinuteLimit != constants.Unlimited {
				return false
			}

			// next check per hour limit
			if (actionQuantity+usageWithinHour > perHourLimit) && perHourLimit != constants.Unlimited {
				return false
			}

			// next check per day limit
			if (actionQuantity+usageWithinDay > perDayLimit) && perDayLimit != constants.Unlimited {
				return false
			}

			// next check per week limit
			if (actionQuantity+usageWithinWeek > perWeekLimit) && perWeekLimit != constants.Unlimited {
				return false
			}

			// next check per fortnight limit
			if (actionQuantity+usageWithinFortnight > perFortnightLimit) && perFortnightLimit != constants.Unlimited {
				return false
			}

			// next check per month limit
			if (actionQuantity+usageWithinMonth > perMonthLimit) && perMonthLimit != constants.Unlimited {
				return false
			}

			// next check per quarter limit
			if (actionQuantity+usageWithinQuarter > perQuarterLimit) && perQuarterLimit != constants.Unlimited {
				return false
			}

			// next check per year limit
			if (actionQuantity+usageWithinYear > perYearLimit) && perYearLimit != constants.Unlimited {
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

func IsEntityActionPermitted(actionType string, entityPermissions Permission) bool {
	// ensure the action type is valid
	if isActionTypeValid(actionType) == false {
		return false
	}

	if actionType == constants.ActionTypeCreate {
		return entityPermissions.Create
	}

	if actionType == constants.ActionTypeRead {
		return entityPermissions.Read
	}

	if actionType == constants.ActionTypeUpdate {
		return entityPermissions.Update
	}

	if actionType == constants.ActionTypeDelete {
		return entityPermissions.Delete
	}

	if actionType == constants.ActionTypeExecute {
		return entityPermissions.Execute
	}

	return false
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

func firstLetterToUppercase(s string) string {
	return strings.ToUpper(string(s[0])) + s[1:]

}

func getEntityPermissionOrder(permissionOrder string) []string {
	var finalOrder []string
	strings.TrimSpace(permissionOrder)
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
	// ensure the action type is correct
	if entityName != constants.EntityOrg &&
		entityName != constants.EntityDomain &&
		entityName != constants.EntityGroup &&
		entityName != constants.EntityRole &&
		entityName != constants.EntityUser {
		return false
	}

	return true
}

//TODO add a way to write this permissions in shorthand , both for obscurity and quick writing of permissions
// Then write a function to intepreter that shorthand, its basically just parsing using strings.split , you might even create your own standard of writing permissions and propose it to a body tasked with standardizing things like this
// FOllowing the unix permission pattern for each entity, you can do , "crud-","c"{all:0,batch:1,minute:0,hour:5,day:0,week:45,fortnight:0,monthly:0,quarterly:0,yearly:0,customDurations:[per_5_minutes_4,per_3_days_50]|r:....

// NotationToPermission converts a notation string to a permission "object"/struct. Its just a useful "shorthand" way to write permissions without using the struct directly
//
// Below is an example of what a notation looks like . Read in the repo documentation for details
//
//	crud-|c=month:0,day:100,batch:1,minute:5,hour:20,week:500,fortnight:700,year:10000,quarter:5000,custom:[per_5_minutes_4 & per_3_days_50]|r=..
func NotationToPermission(notation string) Permission {
	var finalPermission Permission
	// just in case there is space in the string, let's trim space, but there shouldn't be space
	notation = strings.TrimSpace(notation)
	includeThisActionLimit := false
	var currentLimitSection string
	// first let's split the notation into its different section
	if strings.Contains(notation, constants.NotationSectionSeparator) {
		notationSections := strings.Split(notation, constants.NotationSectionSeparator)
		// There should always be 6 sections , if there is less than or more than  6, return empty permissions
		if len(notationSections) != 6 {
			fmt.Println("Malformed permission notation")
			return Permission{}
		}

		// if we got here, it means the notation is properly formed so far
		// let's check the first section if its properly formed, if it is we can proceed,
		// it should always be 5 characters long , because it should be like "crude" , which stands for CREATE, READ, UPDATE, DELETE, EXECUTE . , if we don't want to grant permission to any of these actions any of the letters in "crude" can be replaced with a minus sign "-"
		// But the letter have to ALWAYS follow that order, or be replaced by "-"
		// so let's use regex
		firstSectionPattern := regexp.MustCompile(`^([c-][r-][u-][d-][e-])$`)
		if firstSectionPattern.MatchString(notationSections[0]) == false {
			fmt.Println("Malformed permission notation")
			return Permission{}
		}

		// if we got here it means the pattern matched, and we are good to set the permission values for the actions
		for i, actionPermissionInit := range notationSections[0] {

			if i == 0 {
				if string(actionPermissionInit) == "c" {
					finalPermission.Create = true
				}
			}

			if i == 1 {
				if string(actionPermissionInit) == "r" {
					finalPermission.Read = true
				}
			}

			if i == 2 {
				if string(actionPermissionInit) == "u" {
					finalPermission.Update = true
				}
			}

			if i == 3 {
				if string(actionPermissionInit) == "d" {
					finalPermission.Delete = true
				}
			}

			if i == 4 {
				if string(actionPermissionInit) == "e" {
					finalPermission.Execute = true
				}
			}

		}

		//NOTE document this :

		// Let's move to the remaining sections, we can just loop through them , since they have similar syntax
		// the remaining sections is for limits , create limits for example would be defined like :
		// c=month:0,day:100,batch:1,minute:5,hour:20,week:500,fortnight:700,year:10000,quarter:5000,custom:[per_5_minutes_4,per_3_days_50]
		// for other action types "c=" can just be replaced with "r=" or "u=" or "d=" or "e="
		// Just like the action permission section similarly the proceeding sections should also follow an order
		// e.g c-ude|c=....|r=...|u=...|d=...|e=...
		// Its required that in each action limit section, at least the batch limit should be set
		// The individual limits within each action limit section can be arranged in any order
		// If any limit is excluded, its assumed that the value is unlimited , batch limit can never be unlimited, this is why it's a required limit/value for all action limit sections, where corresponding action permission is granted
		// Let's start the loop , we would be starting the loop from index 1, since index 0 is the actionType permissions which we have already handled
		// Action Limit sections can be left empty if only there corresponding Action permission is not granted .
		// for example if you have crud-|c=.... execute limit can be excluded like this crud-|c=...|r=...|u=...|d=...|- Note the minus sign , in the execute limit section
		for i := 1; i < len(notationSections); i++ {
			//reset include action limit
			includeThisActionLimit = false
			currentLimitSection = ""
			// Let's check if current section is properly formed, this isn't a perfect test for a properly formed action limit section , but it would do for now
			// todo improve this

			// if we are in index 1, ensure it starts with c=, else output error , do same for the other action limits in the correct sequence/order
			if i == 1 {
				if strings.HasPrefix(notationSections[i], "c=") == false && finalPermission.Create == true {
					fmt.Println("Malformed notation: Create action limit section has to start with 'c=', since Create permission is granted ")
					return Permission{}
				}

				if strings.HasPrefix(notationSections[i], "c=") == true && finalPermission.Create == true {
					includeThisActionLimit = true
					currentLimitSection = constants.ActionTypeCreate

				}

			}
			if i == 2 {

				if strings.HasPrefix(notationSections[i], "r=") == false && finalPermission.Read == true {
					fmt.Println("Malformed notation: Read action limit section has to start with 'r=', since Read permission is granted  ")
					return Permission{}
				}
				if strings.HasPrefix(notationSections[i], "r=") == true && finalPermission.Read == true {
					includeThisActionLimit = true
					currentLimitSection = constants.ActionTypeRead

				}
			}

			if i == 3 {
				if strings.HasPrefix(notationSections[i], "u=") == false && finalPermission.Update == true {
					fmt.Println("Malformed notation: Update action limit section has to start with 'u=', since Update permission is granted  ")
					return Permission{}
				}
				if strings.HasPrefix(notationSections[i], "u=") == true && finalPermission.Update == true {
					includeThisActionLimit = true
					currentLimitSection = constants.ActionTypeUpdate

				}
			}
			if i == 4 {
				if strings.HasPrefix(notationSections[i], "d=") == false && finalPermission.Delete == true {
					fmt.Println("Malformed notation: Delete action limit section has to start with 'd=', since Delete permission is granted  ")
					return Permission{}
				}
				if strings.HasPrefix(notationSections[i], "d=") == true && finalPermission.Delete == true {
					includeThisActionLimit = true
					currentLimitSection = constants.ActionTypeDelete

				}
			}

			if i == 5 {
				if strings.HasPrefix(notationSections[i], "e=") == false && finalPermission.Execute == true {
					fmt.Println("Malformed notation: Execute action limit section has to start with 'e=', since Execute permission is granted ")
					return Permission{}
				}
				if strings.HasPrefix(notationSections[i], "e=") == true && finalPermission.Execute == true {
					includeThisActionLimit = true
					currentLimitSection = constants.ActionTypeExecute

				}

			}

			if includeThisActionLimit == true {
				//split and loop through the current action limit to add
				// first split the action key from the limit list
				splitActionLimitSection := strings.Split(notationSections[i], "=")
				// now let's split the limits itself , and assign the limits where they are available, and return the new updated limits
				actionLimit, _ := getNotationActionLimits(splitActionLimitSection[1]) //todo handle error here

				switch currentLimitSection {
				case constants.ActionTypeCreate:
					finalPermission.CreateActionLimits = actionLimit
					break
				case constants.ActionTypeRead:
					finalPermission.ReadActionLimits = actionLimit
					break
				case constants.ActionTypeUpdate:
					finalPermission.UpdateActionLimits = actionLimit
					break
				case constants.ActionTypeDelete:
					finalPermission.DeleteActionLimits = actionLimit
					break
				case constants.ActionTypeExecute:
					finalPermission.ExecuteActionLimits = actionLimit
					break

				}

			}

		}
		return finalPermission
	}
	return Permission{}
}

func isNotationActionBatchLimitSet() {

}

// getNotationActionLimitAndValue receives limit data like "week:5" or "batch:3"
func getNotationActionLimitAndValue(limitData string) (string, uint, bool) {

	limitData = strings.TrimSpace(limitData)
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
	splitLimitData := strings.Split(limitData, constants.NotationActionLimitAndValueSeparator)
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

// getNotationActionCustomLimitValue receives limit data like "custom:[per_5_minutes_10&per_2_month_90]"
func getNotationActionCustomLimitValue(limitData string) ([]string, bool) {
	var customLimitList []string
	limitData = strings.TrimSpace(limitData)

	regexPattern := `^custom:\[((per_[1-9]\d*_[a-z]+_\d+\&)+|(per_[1-9]\d*_[a-z]+_\d+){1})+\]$|^custom:\[\]$`
	regex := regexp.MustCompile(regexPattern)
	if regex.MatchString(limitData) == false {
		return []string{}, false
	}
	// split the limit data since we have verified that its valid
	splitLimitData := strings.Split(limitData, constants.NotationActionLimitAndValueSeparator)
	//limitType :=splitLimitData[0]
	limitValue := splitLimitData[1]

	// remove the value prefix and suffix to denote a list
	limitValue = strings.ReplaceAll(limitValue, constants.NotationCustomLimitValuePrefix, "")
	limitValue = strings.ReplaceAll(limitValue, constants.NotationCustomLimitValueSuffix, "")
	// check if it contains separator
	if strings.Contains(limitValue, constants.NotationCustomLimitValueListSeparator) == false {
		// Since its false , most likely, we have just one custom limit, so lets, just push it
		//todo comeback when you have written validator for the main ActionLimit.CustomDurationsLimit, use the same validator here, since the syntax for the full custom and notation custom limts are the same
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
		//todo comeback when you have written validator for the main ActionLimit.CustomDurationsLimit, use the same validator here, since the syntax for the full custom and notation custom limts are the same
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

func getNotationActionLimits(actionLimitsString string) (ActionLimit, error) {
	var currentActionLimit ActionLimit

	//trim spaces
	actionLimitsString = strings.TrimSpace(actionLimitsString)
	// for scenario where there is just for one limit and there is no separator , just potentially one limit, which has to by design be required to be the batch limit
	if strings.Contains(actionLimitsString, constants.NotationActionLimitsSeparator) == false {
		// now we check the string if it at least has the format limit:value e.g batch:3,
		// so it has to at least contain ":", and then when split , should be at least a len of 2
		// we also need to make sure that we don't have more than one ":", this is to ensure that users always separate the limits with comma
		if strings.Contains(actionLimitsString, constants.NotationActionLimitAndValueSeparator) == true && strings.Count(actionLimitsString, constants.NotationActionLimitAndValueSeparator) == 1 {
			splitSingleLimit := strings.Split(actionLimitsString, constants.NotationActionLimitAndValueSeparator)
			// the len has to be at exactly 2, else it's not valid
			if len(splitSingleLimit) == 2 {
				// Now that we are here, if we have gotten to this point it means there is only one valid limit for this action Limit,
				// But "batch" limit is a required limit, if this limit isn't batch limit, there is no need continuing
				if strings.ToLower(splitSingleLimit[0]) == constants.NotationActionBatchLimitKey {
					// check the limit, it has to be greater than 0
					batchLimit, batchLimitErr := strconv.ParseUint(splitSingleLimit[1], 10, 64)
					if batchLimitErr == nil && batchLimit > 0 {
						currentActionLimit.BatchLimit = uint(batchLimit)
						//return back the action limit , with the batch limit added
						return currentActionLimit, nil

					}
				}
			}
		}
		fmt.Println("malformed notation action limits, check that its properly formed, and has the required limits")
		return currentActionLimit, fmt.Errorf("malformed notation action limits, check that its properly formed, and has the required limits")
	}

	// for other scenarios where the separator is included, possibly indicating multiple limits
	if strings.Contains(actionLimitsString, constants.NotationActionLimitsSeparator) == true {
		splitLimits := strings.Split(actionLimitsString, constants.NotationActionLimitsSeparator)
		if len(splitLimits) > 0 {

			// loop through the limits in the slice
			// if any of the limits or its value is invalid, return error
			for i := 0; i < len(splitLimits); i++ {
				currentLimitData := splitLimits[i]
				// check if current limit data contains the right seprator is
				// if its not custom limit
				if strings.Contains(currentLimitData, constants.NotationActionCustomLimitKey) == true {
					customLimitSlice, isCustomLimitValid := getNotationActionCustomLimitValue(currentLimitData)
					if isCustomLimitValid {
						currentActionLimit.CustomDurationsLimit = customLimitSlice
					} else {
						fmt.Println("malformed notation action limits, check that the custom limits are properly formed")
					}
				} else {
					// for other limits
					currentLimitType, currentLimitValue, isCurrentLimitDataValid := getNotationActionLimitAndValue(currentLimitData)

					if isCurrentLimitDataValid == true { // set batch limit
						if currentLimitType == constants.NotationActionBatchLimitKey {
							currentActionLimit.BatchLimit = currentLimitValue
						}

						// set all time limit
						if currentLimitType == constants.NotationActionAllTimeLimitKey {
							currentActionLimit.AllTimeLimit = currentLimitValue
						}
						// set all minute limit
						if currentLimitType == constants.NotationActionMinuteLimitKey {
							currentActionLimit.PerMinuteLimit = currentLimitValue
						}
						// set all hour limit
						if currentLimitType == constants.NotationActionHourLimitKey {
							currentActionLimit.PerHourLimit = currentLimitValue
						}
						// set all day limit
						if currentLimitType == constants.NotationActionDayLimitKey {
							currentActionLimit.PerDayLimit = currentLimitValue
						}
						// set all week limit
						if currentLimitType == constants.NotationActionWeekLimitKey {
							currentActionLimit.PerWeekLimit = currentLimitValue
						}

						// set all fortnight limit
						if currentLimitType == constants.NotationActionFortnightLimitKey {
							currentActionLimit.PerFortnightLimit = currentLimitValue
						}

						// set all month limit
						if currentLimitType == constants.NotationActionMonthLimitKey {
							currentActionLimit.PerMonthLimit = currentLimitValue
						}

						// set all quarter limit
						if currentLimitType == constants.NotationActionQuarterLimitKey {
							currentActionLimit.PerQuarterLimit = currentLimitValue
						}

						// set all year limit
						if currentLimitType == constants.NotationActionYearLimitKey {
							currentActionLimit.PerYearLimit = currentLimitValue
						}
					} else {
						fmt.Println("malformed notation action limits, check that its properly formed, and has the required limits")
					}

				}
			}

		}
		return currentActionLimit, nil
	}

	return currentActionLimit, fmt.Errorf("unknown error") //todo come back and improve this error message

}
