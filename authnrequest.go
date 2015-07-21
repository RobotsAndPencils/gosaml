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
	"github.com/nu7hatch/gouuid"
)

func NewAuthorizationRequest(appSettings AppSettings, accountSettings AccountSettings) *AuthorizationRequest {
	myIdUUID, err := uuid.NewV4()
	if err != nil {
		fmt.Println("Error is UUID Generation:", err)
	}

	return &AuthorizationRequest{AccountSettings: accountSettings, AppSettings: appSettings, Id: "_" + myIdUUID.String()}
}

// GetRequest returns a string formatted XML document that represents the SAML document
// TODO: parameterize more parts of the request
func (ar AuthorizationRequest) GetRequest(base64Encode bool) (string, error) {
	d := structs.NewAuthnRequest()
	d.ID = ar.Id
	d.AssertionConsumerServiceURL = ar.AppSettings.AssertionConsumerServiceURL
	d.Issuer.Url = ar.AppSettings.AssertionConsumerServiceURL
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}

	xmlAuthnRequest := fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b)

	if base64Encode {
		data := []byte(xmlAuthnRequest)
		return base64.StdEncoding.EncodeToString(data), nil
	} else {
		return string(xmlAuthnRequest), nil
	}
}

// GetSignedRequest returns a string formatted XML document that represents the SAML document
// TODO: parameterize more parts of the request
func (ar AuthorizationRequest) GetSignedRequest(base64Encode bool, publicCert string, privateKey string) (string, error) {
	cert, err := LoadCertificate(publicCert)
	if err != nil {
		return "", err
	}

	d := structs.NewAuthnSignedRequest()
	d.ID = ar.Id
	d.AssertionConsumerServiceURL = ar.AppSettings.AssertionConsumerServiceURL
	d.Issuer.Url = ar.AppSettings.AssertionConsumerServiceURL
	d.Signature.SignedInfo.SamlsigReference.URI = "#" + ar.Id
	d.Signature.KeyInfo.X509Data.X509Certificate.Cert = cert

	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}

	samlAuthnRequest := string(b)
	samlSignedRequestXml, err := xmlsec.SignRequest(samlAuthnRequest, privateKey)

	if base64Encode {
		data := []byte(samlSignedRequestXml)
		return base64.StdEncoding.EncodeToString(data), nil
	} else {
		return string(samlSignedRequestXml), nil
	}
}

// String reqString = accSettings.getIdp_sso_target_url()+"?SAMLRequest=" +
// AuthRequest.getRidOfCRLF(URLEncoder.encode(authReq.getRequest(AuthRequest.base64),"UTF-8"));
func (ar AuthorizationRequest) GetRequestUrl() (string, error) {
	u, err := url.Parse(ar.AccountSettings.IDP_SSO_Target_URL)
	if err != nil {
		return "", err
	}
	base64EncodedUTF8SamlRequest, err := ar.GetRequest(true)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("SAMLRequest", base64EncodedUTF8SamlRequest)

	u.RawQuery = q.Encode()
	return u.String(), nil
}
