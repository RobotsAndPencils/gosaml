package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"time"

	"github.com/RobotsAndPencils/gosaml/structs"
	"github.com/RobotsAndPencils/gosaml/xmlsec"
)

func (s *ServiceProviderSettings) Parse(b64ResponseXML string) (map[string]string, error) {
	response := structs.Response{}
	rtn := make(map[string]string)
	bytesXML, err := base64.StdEncoding.DecodeString(b64ResponseXML)
	if err != nil {
		return rtn, err
	}

	err = xml.Unmarshal(bytesXML, &response)
	if err != nil {
		return rtn, err
	}

	err = xmlsec.VerifyResponseSignature(string(bytesXML), s.PublicCert())
	if err != nil {
		return rtn, err
	}

	err = s.IsValid(&response)
	if err != nil {
		return rtn, err
	}

	for _, attr := range response.Assertion.AttributeStatement.Attributes {
		rtn[attr.Name] = attr.AttributeValue.Value

		if attr.FriendlyName != "" {
			rtn[attr.FriendlyName] = attr.AttributeValue.Value
		}
	}

	return rtn, err

}

func (s *ServiceProviderSettings) IsValid(response *structs.Response) error {
	if response.Version != "2.0" {
		return errors.New("unsupported SAML Version")
	}

	if len(response.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}

	if len(response.Assertion.ID) == 0 {
		return errors.New("no Assertions")
	}

	if len(response.Signature.SignatureValue.Value) == 0 {
		return errors.New("no signature")
	}

	if response.Destination != s.AssertionConsumerServiceURL {
		return errors.New("destination mismath expected: " + s.AssertionConsumerServiceURL + " not " + response.Destination)
	}

	if response.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("assertion method exception")
	}

	if response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != s.AssertionConsumerServiceURL {
		return errors.New("subject recipient mismatch, expected: " + s.AssertionConsumerServiceURL + " not " + response.Destination)
	}

	//CHECK TIMES
	expires := response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
	notOnOrAfter, e := time.Parse(time.RFC3339, expires)
	if e != nil {
		return e
	}
	if notOnOrAfter.Before(time.Now()) {
		return errors.New("assertion has expired on: " + expires)
	}

	return nil
}
