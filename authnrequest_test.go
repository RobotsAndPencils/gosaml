package saml

import (
	"testing"

	"github.com/RobotsAndPencils/gosaml/xmlsec"
	"github.com/stretchr/testify/assert"
)

func TestGetSignedRequest(t *testing.T) {
	assert := assert.New(t)
	appSettings := NewAppSettings("http://www.onelogin.net", "issuer")
	accountSettings := NewAccountSettings("cert", "http://www.onelogin.net")

	// Construct an AuthnRequest
	authRequest := NewAuthorizationRequest(appSettings, accountSettings)
	signedXml, err := authRequest.GetSignedRequest(false, "./default.crt", "./default.key")
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = xmlsec.VerifyRequestSignature(signedXml, "./default.crt")
	assert.NoError(err)
}
