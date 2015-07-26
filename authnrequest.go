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
	"time"

	"github.com/RobotsAndPencils/gosaml/util"
)

// GetAuthnRequest returns an XML document that represents a AuthnRequest SAML document
func (s *ServiceProviderSettings) GetAuthnRequest() (string, error) {
	d := NewAuthnRequest()
	d.AssertionConsumerServiceURL = s.AssertionConsumerServiceURL
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
	d := NewAuthnSignedRequest()
	d.AssertionConsumerServiceURL = s.AssertionConsumerServiceURL
	d.Issuer.Url = s.IDPSSODescriptorURL
	d.Signature.KeyInfo.X509Data.X509Certificate.Cert = s.PublicCert()

	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}

	samlAuthnRequest := string(b)
	samlSignedRequestXML, err := SignRequest(samlAuthnRequest, s.PrivateKeyPath)
	if err != nil {
		return "", err
	}

	return string(samlSignedRequestXML), nil
}

// GetAuthnRequestURL generate a URL for the AuthnRequest to the IdP with the SAMLRequst parameter encoded
func (s *ServiceProviderSettings) GetAuthnRequestURL(authnRequestXML string) (string, error) {
	u, err := url.Parse(s.IDPSSOURL)
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

func NewAuthnRequest() *AuthnRequest {
	return &AuthnRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		SAMLP:                       "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:                        "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:                          util.ID(),
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Version:                     "2.0",
		AssertionConsumerServiceURL: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url:  "", // caller must populate ar.AppSettings.Issuer
			SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
		},
		IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
		NameIDPolicy: NameIDPolicy{
			XMLName: xml.Name{
				Local: "samlp:NameIDPolicy",
			},
			AllowCreate: true,
			Format:      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
		RequestedAuthnContext: RequestedAuthnContext{
			XMLName: xml.Name{
				Local: "samlp:RequestedAuthnContext",
			},
			SAMLP:      "urn:oasis:names:tc:SAML:2.0:protocol",
			Comparison: "exact",
			AuthnContextClassRef: AuthnContextClassRef{
				XMLName: xml.Name{
					Local: "saml:AuthnContextClassRef",
				},
				SAML:      "urn:oasis:names:tc:SAML:2.0:assertion",
				Transport: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
	}
}

func NewAuthnSignedRequest() *AuthnSignedRequest {
	id := util.ID()
	return &AuthnSignedRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		SAMLP:                       "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:                        "urn:oasis:names:tc:SAML:2.0:assertion",
		SAMLSIG:                     "http://www.w3.org/2000/09/xmldsig#",
		ID:                          id,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Version:                     "2.0",
		AssertionConsumerServiceURL: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
		},
		IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
		NameIDPolicy: NameIDPolicy{
			XMLName: xml.Name{
				Local: "samlp:NameIDPolicy",
			},
			AllowCreate: true,
			Format:      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
		RequestedAuthnContext: RequestedAuthnContext{
			XMLName: xml.Name{
				Local: "samlp:RequestedAuthnContext",
			},
			SAMLP:      "urn:oasis:names:tc:SAML:2.0:protocol",
			Comparison: "exact",
			AuthnContextClassRef: AuthnContextClassRef{
				XMLName: xml.Name{
					Local: "saml:AuthnContextClassRef",
				},
				SAML:      "urn:oasis:names:tc:SAML:2.0:assertion",
				Transport: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},

		Signature: Signature{
			XMLName: xml.Name{
				Local: "samlsig:Signature",
			},
			Id: "Signature1",
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "samlsig:SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "samlsig:CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "samlsig:SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "samlsig:Reference",
					},
					URI: "#" + id,
					Transforms: Transforms{
						XMLName: xml.Name{
							Local: "samlsig:Transforms",
						},
						Transform: Transform{
							XMLName: xml.Name{
								Local: "samlsig:Transform",
							},
							Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
						},
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "samlsig:DigestMethod",
						},
						Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "samlsig:DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "samlsig:SignatureValue",
				},
			},
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "samlsig:KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "samlsig:X509Data",
					},
					X509Certificate: X509Certificate{
						XMLName: xml.Name{
							Local: "samlsig:X509Certificate",
						},
						Cert: "", // caller must populate cert,
					},
				},
			},
		},
	}
}
