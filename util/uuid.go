package util

import "github.com/nu7hatch/gouuid"

// UUID generate a new V4 UUID
func UUID() string {
	u, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	return u.String()
}
