package ssn

import "github.com/google/osv-scalibr/veles/sensitiveinformation"

type ModelSocialSecurityNumber struct {
	sensitiveinformation.SensitiveInformation
	Number string
}
