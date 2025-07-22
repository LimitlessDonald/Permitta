Permitta is an intuitive go library, which aims to help handle any kind of permission/access control in a simple and easy to understand way, even for beginners .

The fact that its intuitive doesn't take away how powerful it is to handle very complex and frequently used permission scenarios in different types of projects .


## Why

Almost everything we do in computing these days needs permissions . There are hundreds of permission/access control systems and methods, many of them are not intuitive .

I wanted to create a system that would cover most popular use cases, where you can get started in minutes, whether you are a novice or very experienced programmer, yet still powerful enough to handle complex permissions .

I took inspiration from the linux permission system e.g ``` rwxr--r-x ```, but took it some steps further and made it more intuitive

I wanted to be able to handle permissions/access control in a SaaS (or any application), with multiple access levels and users

I wanted to be able to control access for actions including Create, Read, Update, Delete, Execute (remember **CRUDE** - more on this later), I wanted to be able to control how much of each of those actions can be carried out by each user, and how frequently within a specific period of time they can carry out those actions .

I wanted to create a permission/access control system with no dependencies, except the go standard library

I wanted to enjoy writing and reading permissions/access control

I wanted to be able to write extremely complex permissions/access control for a user/org/entity on a single line

I did not want to have to write complex DB queries to verify permission and resource usage, which can get very tedious as an application gets more complex.




## Features

- Ability to set create, read, update , delete, execute (CRUDE) operations permissions
- Ability to control start and end time for permissions
- Ability to set quota limit (Quota is how many of a certain resource can exist at any given time)
- Ability to set batch limit
- Ability to set time based limits (all time , per minute, per hour, per day, per week, per fortnight, per month, per quarter, per year, custom time duration [in progress] )
- Ability to verify permission against usage (you would need to store usage in your preferred DB )
- Ability to verify permissions based on entity i.e (user, role, group, domain, organisation)
- Ability to set entity permission order    (the flow/order in which the permission should be checked e.g org->domain->group->role->user)

## Installation
```shell
go get -u github.com/limitlessDonald/permitta
```
## Usage


### Example Scenario 1 - A file management software as a service with multiple users
1. Assume there is a file `file2.mp4` belonging to user ; `eagle`
2. Assume we have a database with three columns `username`, `filename`, `permission`
3. Assume we have an existing function that saves file permission to database called `saveFilePermission`, the package currently doesn't save permissions for you, you have to implement that whichever way you deem fit in your application
4. Assume we have a function that gets file permission for a certain user called `getFilePermission`


```go
package main

import (
	"fmt"
	"github.com/limitlessDonald/permitta"
	
	permittaConstants "github.com/limitlessDonald/permitta/constants"
	
)

func main() {
	// There are two ways to set permission , we can make use of notation(shorthand) and using structs using permitta.Permission{}
	// if we want to set a very simple permission for the eagle user we could do this : 
	username := "eagle"
	filename := "file2.mp4"
	// Now we set the permission using notation 
	// This permission means `eagle` would be able to Create(c) , Read(r), Update(u), Delete(d), and Execute(e) the `file2.mp4` file  
	// If we want to remove/disallow permission to a certain operation, we replace it with a hypen , so "cru-e" , would mean that delete operations are not permitted 
	notation := "crude"

	// we can now save it to db for use / access control later
	isFilePermissionSaved := saveFilePermission(username, filename, notation)
	if isFilePermissionSaved == false {
		fmt.Println("There was an issue saving file permission")
	}

	//If eagle tries to execute the file (an execution operation), we want to check if eagle has the permission to do so, here is how we do it 
	// assume getFilePermission returns the saved permission 
	currentUserPermission := getFilePermission(username, filename)

	// Now let's verify if user has permission to execute file 
	// since the permission is saved as notation string, we want to convert it to the type permitta.Permission{}
	permissions := permitta.NotationToPermission(currentUserPermission)

	isUserPermitted := permitta.IsEntityOperationPermitted(permittaConstants.OperationExecute,permissions)
	if isUserPermitted==true {
		fmt.Println("Running program ....")
    }

}

```
### Example Scenario 2 - A farm management SaaS (Software as a  Service)
The power of permitta may not be evident from the simple example above, lets create a more complex permission/access control system to reveal more of its power

Let's take some assumptions and facts into consideration to make the example easier to understand

1. Assume there are many farms registered on the farm management SaaS, each of this farm is an `organization`, one of them is a farm called `Blue Acres Farm`
2. Assume there are multiple `domains` or more precisely `Blue Acres Farm` has multiple branches , one in the US and another in the France. The US and France branches are `domains`
3. Assume there are multiple `groups` , or more precisely departments in each of the `domains` , like Accounting , Marketing, Sales, IT, Engineering e.t.c
4. Assume there are `roles` in each of the `groups` , take for example the `Accounting` group/department , could have roles like `Budgeting Manager`, `Auditor` and the `Engineering` could have `Maintenance Engineer` and `Electrical Engineer`
5. Assume there are `users` for each of these `roles` , e.g there could be multiple `Budgeting Managers` , like users `Anna` and `Pierre`
6. Organization, domain, group, role, user in permitta are all described as `entities` . So the `user` , `Anna` is an `entity`, just like her role `Budgeting Manager` is an `entity`

Now that we have all the above cleared up, before we go into a full code example, let's do a brief "anatomy" of what a very complex permission notation for an entity looks like and explain it
```

 notation:="cr-d-|start=1735693200000|end=1767229200000|q=5|c=batch:2,all:100,minute:3,hour:103,day:7,week:20,fortnight:30|r=all:100000,quarter:80000|u=year:10000,month:5000,custom:[per_32_seconds_67 & per_9_weeks_1200]"
 ```
**Explanation:**
- The notation is divided into sections using the separator `|`
- The first section `cr-d-` means : `c` Create operation allowed, `r` read allowed, `-` update NOT allowed, `d` delete allowed, `-` execute not allowed
  -`start=1735693200000` means the entity won't be permitted for anything, if a permission request is made before the unix time `1735693200000`. In other words permission starts at this time
- `end=1767229200000` means permission ends at this time `1767229200000`
- `q=5` means Quota=5 , this is useful when you store resource/operation usage/count in a DB . if `q=5` for videos for example for the Engineering department/`group`, at any given time, they can't have more than 5 videos stored
- Any section starting with `c=`,`r=`,`u=`,`d=`,`e=` is for defining limits for specific operation where `c=` is for `Create` operation limits and so on.
- See [Operation Limits](#operation-limits) for all the available limits and what they mean
- The next section `c=batch:2,all:100,minute:3,hour:103,day:7,week:20,fortnight:30`
  1. As we already highlighted above `c=` means "The following limits are for `create` operations"
  2. `batch=2` means the entity can't create more than two resources at a time
  3. `all:100` means the all-time limit of resources that can be created by the entity is `100`, not to be confused with `Quota`, See [Operation Limits](#operation-limits) to understand the difference
  4. `minute:3` means only `3` resources can be created by the entity every minute. Permission would be denied if the entity tries to create a fourth resource within a minute
  5. `hour:100`,`day:7`,`week:20`,`fortnight:30` are similar to the explanation for the `minute` limit
- I believe the remaining sections should be self-explanatory , except where we have `custom:[per_32_seconds_67 & per_9_weeks_1200]` **NOTE THAT CUSTOM DURATION IS STILL UNDER DEVELOPMENT** . However, it simply means we have a list of custom durations :
  1. `per_32_seconds_67` means the entity is allowed to perform `67` `update` operations `every 32 seconds`
  2. `&` is the separator for the list of custom duration limits
  3. `per_9_weeks_1200` means the entity is allowed to perform `1200` `update` operations `every 9 weeks`
- If limits for any operation is left out from the notation, the default for all the limits would be unlimited, except `batch` which is always `1` by default
- **NOTE** : For limits to work, it has to be paired with `usages` that you have stored in your preferred DB, Permitta provides a self-explanatory struct to help store usages and a function to easily update usage


Let's proceed with the example

```go
// Assume we have `usage` column in each db table for org,branches(domain),departments(group),roles,users
// The column can be named anything, Permitta NEVER directly interacts with your DB

// if the usage has not being previously saved by you, we could initialize it with
jsonBytes, err := json.Marshal(permitta.PermissionUsage{})
if err != nil {
  fmt.Println(err)
  return
}
// save usage as json string to the `usage` column 
// saveOrgUsage,saveBranchUsage,saveDepartmentUsage,saveRoleUsage,saveUserUsage are assumed functions in your code to save the usage values, they don't exist in Permitta. Permitta doesn't save to our DB for you
saveOrgUsage(orgID,string(jsonBytes))
saveBranchUsage(branchID,string(jsonBytes))
saveDepartmentUsage(departmentID,string(jsonBytes))
saveRoleUsage(roleID,string(jsonBytes))
saveUserUsage(userID,string(jsonBytes))

```


```go


// Let's assume we fetch notation for each entity from the DB, and convert it to permissions 
orgPermission:=permitta.NotationToPermission("crude") // unlimited access / permissions 
franceBranchPermission:=permitta.NotationToPermission("cru-e|q=9000|c=batch:50") //domain permissions
financeDepartmentPermission := permitta.NotationToPermission("cru--|c=hour:30") //group permissions
auditInternPermission:=permitta.NotationToPermission("-r---|r=hour:500") // role permissions

// there is a new intern in the france branch called Adesewa, she is in the finance department, she has a role of Audit intern, let's create her permission
adesewaPermission:=permitta.NotationToPermission("crude|r=hour:10|start=1735693200000|end=1767229200000") // user permissions


// Let's check permission if Adesewa tries to delete a file since her permission allows her to delete a resource

// to check permission we have to check this against her usage, the usage and permission of her role, the usage and permission of her department, the usage and permission of her branch and org
// let's get all saved usage json and convert it to permitta.PermissionUsage
orgUsageJson:=getOrgUsage(orgID)
branchUsageJson:=getBranchUsage(branchID)
departmentUsageJson:=getDepartmentUsage(departmentID)
roleUsageJson:=getRoleUsage(roleID)
userUsageJson:=getUserUsage(userID)

// Ideally you can write a function to just do this for all the usage so you don't repeat yourself unnecessarily . OR include the conversion in your get-Entity-Usage functions like getOrgUsage 
// I am intentionally making this as clear as possible, so beginners can understand what is going on in details 
var orgUsage permitta.PermissionUsage
var branchUsage permitta.PermissionUsage
var departmentUsage permitta.PermissionUsage
var roleUsage permitta.PermissionUsage
var userUsage permitta.PermissionUsage

// convert json string to permitta.PermissionUsage
orgUsageErr := json.Unmarshal([]byte(orgUsageJson), &orgUsage)

if orgUsageErr != nil {
  fmt.Println(orgUsageErr)
  return "AccessDenied"
}


branchUsageErr := json.Unmarshal([]byte(branchUsageJson), &branchUsage)

if branchUsageErr != nil {
  fmt.Println(branchUsageErr)
  return "AccessDenied"
}


departmentUsageErr := json.Unmarshal([]byte(departmentUsageJson), &departmentUsage)

if departmentUsageErr != nil {
  fmt.Println(departmentUsageErr)
  return "AccessDenied"
}


roleUsageErr := json.Unmarshal([]byte(roleUsageJson), &roleUsage)

if roleUsageErr != nil {
  fmt.Println(roleUsageErr)
  return "AccessDenied"
}


userUsageErr := json.Unmarshal([]byte(userUsageJson), &userUsage)

if userUsageErr != nil {
  fmt.Println(userUsageErr)
  return "AccessDenied"
}


// Now it's time to check permission 
// The EntityPermissionOrder is the "flow" or hierarchy in which the permissions should be respected 
// This org->domain->group->role->user , means org permissions and usage are taken into consideration first to check if the operation is permitted, if it isn't the permission check stops there and returns FALSE, if its permission is ok, it moves to the next entity domain, and so on
// if EntityPermissionOrder is not provided , the default is org->domain->group->role->user 
// You don't have to use all the entities in the permission order, to ignore anyone, just leave it out .
// this means role->user is also valid 
// How you order things is totally up to you and how your application is designed 
permissionRequestData := permitta.PermissionWithUsageRequestData{
    PermissionRequestData: PermissionRequestData{
        Operation:               permittaConstants.OperationDelete,
        UserEntityPermissions:   adesewaPermission,
        RoleEntityPermissions:   auditInternPermission,
        GroupEntityPermissions:  financeDepartmentPermission,
        DomainEntityPermissions: franceBranchPermission,
        OrgEntityPermissions:    orgPermission,
        EntityPermissionOrder:   "org->domain->group->role->user",
    },
    OperationQuantity: 2, // the amount of operation we are requesting permission for at this time. This also checks against the batch limit of each entity 
    UserEntityUsage: userUsage,
    RoleEntityUsage:   roleUsage,
    GroupEntityUsage:  departmentUsage,
    DomainEntityUsage: branchUsage,
    OrgEntityUsage: orgUsage,
}
isUserOperationPermittedWithUsage:= permitta.IsOperationPermittedWithUsage(permissionRequestData)

if isUserOperationPermittedWithUsage==true{
	// since permission is granted, after performing the operation in your code. E.g deleting a file, you would want to update Usage 
	// Since this is a Delete operation, the QuotaUsage for each entity's PermissionUsage would be reduced by the value of the OperationQuantity 
	// If this was a Create operation, the QuotaUsage would increase
    updateUsageData:=UpdateUsageData{
		
      Operation:                    permittaConstants.OperationDelete,
      OperationQuantity:             2,
      OperationTime:                 time.Now(),
    }
	
    newUsageForOrg:=permitta.UpdateUsage(updateUsageData,orgUsage)
    newUsageForBranch:=permitta.UpdateUsage(updateUsageData,branchUsage)
    newUsageForDepartment:=permitta.UpdateUsage(updateUsageData,departmentUsage)
    newUsageForRole:=permitta.UpdateUsage(updateUsageData,roleUsage)
    newUsageForAdesewa:=permitta.UpdateUsage(updateUsageData,userUsage)
	
	// we are assuming we have a struct to json function, to make this example code shorter . its basically just json.Marshal
	// Let's update usage for each entity in the DB 
    saveOrgUsage(orgID,structToJsonString(newUsageForOrg))
    saveBranchUsage(branchID,structToJsonString(newUsageForBranch))
    saveDepartmentUsage(departmentID,structToJsonString(newUsageForDepartment))
    saveRoleUsage(roleID,structToJsonString(newUsageForRole))
    saveUserUsage(userID,structToJsonString(newUsageForAdesewa))
	return "AccessGranted"
}else{
	return "AccessDenied"
}



```

What do you think the result of the permission request would be ?

Its going to be `AccessDenied`

Why ?

Here is why :

We are trying to carry out a `delete` operation. Adesewa's permission allows a delete operation, but because the  permissions higher in the hierarchy as defined with `EntityPermissionOrder` for `domain`, `group` and `role` entities DO NOT permit `delete` operations

I believe this explains how permitta works. I would be improving this documentation soon, there is still so much it can do I have not documented yet .

## Operation Limits
- **Batch** (notation key (NK) =`batch`) - How many resources for a certain operations is permitted at a time, if not defined, default limit is 1. e.g requesting permission to create 5 files at a time
- **AllTime limit** (NK=`all` ) = The total count of a particular operation that can be carried out by an entity, regardless of other limits . A use case is a scenario where daily limit of creating files is 10 files, if 10 files are created that day, one is deleted, and one new file is created, 11 files have been created. if the AllTime limit is 100 for `create` operation, this means there is remaining allowance to create new files is now (100-11)=89, regardless of what the weekly, monthly, yearly limit is. The default for this limit if not defined is unlimited
- **Minute** (NK=`minute`) = The total count of how much an entity is permitted carry out an operation for a resource per minute
- **Hour** (NK=`hour`) = The total count of how much an entity is permitted carry out an operation for a resource per hour
- **Day** (NK=`day`) = The total count of how much an entity is permitted carry out an operation for a resource per day
- **Week** (NK=`week`) = The total count of how much an entity is permitted carry out an operation for a resource per week
- **Fortnight** (NK=`fortnight`) = The total count of how much an entity is permitted carry out an operation for a resource per fortnight (14 days)
- **Month** (NK=`month`) = The total count of how much an entity is permitted carry out an operation for a resource per month (30 days )
- **Quarter** (NK=`quarter`) = The total count of how much an entity is permitted carry out an operation for a resource per month (90 days )
- **Year** (NK=`year`) = The total count of how much an entity is permitted carry out an operation for a resource per year (360 days )
- **Custom** (NK=`custom`) = Custom duration limit of any kind (`Work in Progress`)



## Limits Defaults when not defined
1. Batch is always 1 for all operations
2. Every other limit is unlimited

## Roadmap
1. Improve readme documentation
2. Improve code documentation
3. Improve error handling
4. Clean up unused code
5. Make handling permission with usage simpler
6. Do proper test coverage
7. If operation is not permitted include some feedback on why operation is not permitted

## License : MIT

## Notice:
If you are hiring, I am currently open . Kindly send me a message https://x.com/LimitlessDonald
