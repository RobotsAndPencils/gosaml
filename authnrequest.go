// Copyright 2014 Matthew Baird, Andrew Mussey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package saml

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/url"

	"github.com/RobotsAndPencils/gosaml/structs"
	"github.com/RobotsAndPencils/gosaml/xmlsec"
)

// GetAuthnRequest returns an XML document that represents a AuthnRequest SAML document
func (s *ServiceProviderSettings) GetAuthnRequest() (string, error) {
	d := structs.NewAuthnRequest()
	d.Issuer.Url = s.IDPSSODescriptorURL
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}

	xmlAuthnRequest := fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b)

	return string(xmlAuthnRequest), nil
}

// GetSignedAuthnRequest returns a singed XML document that represents a AuthnRequest SAML document
func (s *ServiceProviderSettings) GetSignedAuthnRequest() (string, error) {
	d := structs.NewAuthnSignedRequest()
	d.Issuer.Url = s.IDPSSODescriptorURL
	d.Signature.KeyInfo.X509Data.X509Certificate.Cert = s.PublicCert()

	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}

	samlAuthnRequest := string(b)
	samlSignedRequestXml, err := xmlsec.SignRequest(samlAuthnRequest, s.PrivateKeyPath)
	if err != nil {
		return "", err
	}

	return string(samlSignedRequestXml), nil
}

func (s *ServiceProviderSettings) GetAuthnRequestURL(authnRequestXML string) (string, error) {
	u, err := url.Parse(s.IDPSSODescriptorURL)
	if err != nil {
		return "", err
	}

	data := []byte(authnRequestXML)
	b64XML := base64.StdEncoding.EncodeToString(data)

	q := u.Query()
	q.Add("SAMLRequest", b64XML)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
