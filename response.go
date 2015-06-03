package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"time"
)

func Parse(resp string, appSettings *AppSettings, accountSettings *AccountSettings) (map[string]string, error) {
	x := Response{}
	rtn := make(map[string]string)
	decode, err := base64.StdEncoding.DecodeString(resp)
	if err != nil {
		return rtn, err
	}

	err = xml.Unmarshal(decode, &x)
	if err != nil {
		return rtn, err
	}

	err = VerifySignature(string(decode), accountSettings.Certificate)
	if err != nil {
		return rtn, err
	}

	err = IsValid(&x, appSettings, accountSettings)
	if err != nil {
		return rtn, err
	}

	for _, attr := range x.Assertion.AttributeStatement.Attributes {
		rtn[attr.Name] = attr.Value

		if attr.FriendlyName != "" {
			rtn[attr.FriendlyName] = attr.Value
		}
	}

	return rtn, err

}

func IsValid(x *Response, appSettings *AppSettings, accountSettings *AccountSettings) error {
	if x.Version != "2.0" {
		return errors.New("unsupported SAML Version.")
	}

	if len(x.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response.")
	}

	if len(x.Assertion.ID) == 0 {
		return errors.New("no Assertions.")
	}

	if len(x.Signature.SignatureValue.Value) == 0 {
		return errors.New("no signature.")
	}

	if x.Destination != appSettings.AssertionConsumerServiceURL {
		return errors.New("destination mismath expected: " + appSettings.AssertionConsumerServiceURL + " not " + x.Destination)
	}

	if x.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("assertion method exception")
	}

	if x.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != appSettings.AssertionConsumerServiceURL {
		return errors.New("subject recipient mismatch, expected: " + appSettings.AssertionConsumerServiceURL + " not " + x.Destination)
	}

	//CHECK TIMES
	expires := x.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
	notOnOrAfter, e := time.Parse(time.RFC3339, expires)
	if e != nil {
		return e
	}
	if notOnOrAfter.Before(time.Now()) {
		return errors.New("assertion has expired on: " + expires)
	}

	return nil
}
