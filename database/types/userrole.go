package types

import "fmt"

type UserRole int64

const (
	RoleMember UserRole = iota
	RoleAdmin
	RoleToDelete
)

func (r UserRole) String() string {
	switch r {
	case RoleMember:
		return "Member"
	case RoleAdmin:
		return "Admin"
	case RoleToDelete:
		return "ToDelete"
	}
	return fmt.Sprintf("UserRole{ %d }", r)
}

func (r UserRole) IsValid() bool {
	return r == RoleMember || r == RoleAdmin
}
