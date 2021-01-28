package common

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPrincipalToSPIFFE(t *testing.T) {
	cases := []struct {
		test           string
		principal      string
		expectedSpiffe string
		expectedErr    error
	}{
		{
			test:           "empty principal",
			principal:      "",
			expectedSpiffe: "",
			expectedErr:    fmt.Errorf("principal is empty"),
		},
		{
			test:           "valid service principal",
			principal:      "client.some-domain.dep-svcA",
			expectedSpiffe: "client.some-domain/sa/dep-svcA",
			expectedErr:    nil,
		},
		{
			test:           "valid user principal",
			principal:      "user.myname",
			expectedSpiffe: "user/sa/myname",
			expectedErr:    nil,
		},
		{
			test:           "invalid principal",
			principal:      "someuser",
			expectedSpiffe: "",
			expectedErr:    fmt.Errorf("principal:someuser is not of the format <Athenz-domain>.<Athenz-service>"),
		},
	}

	for _, c := range cases {
		gotSpiffe, gotErr := PrincipalToSpiffe(c.principal)
		assert.Equal(t, c.expectedSpiffe, gotSpiffe, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}
