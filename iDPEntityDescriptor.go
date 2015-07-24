package saml

import (
	"encoding/xml"
	"fmt"

	"github.com/RobotsAndPencils/gosaml/structs"
)

func (s *ServiceProviderSettings) GetEntityDescriptor() (string, error) {
	d := structs.EntityDescriptor{
		XMLName: xml.Name{
			Local: "md:EntityDescriptor",
		},
		DS:       "http://www.w3.org/2000/09/xmldsig#",
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		MD:       "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityId: s.AssertionConsumerServiceURL,

		Extensions: structs.Extensions{
			XMLName: xml.Name{
				Local: "md:Extensions",
			},
			Alg:    "urn:oasis:names:tc:SAML:metadata:algsupport",
			MDAttr: "urn:oasis:names:tc:SAML:metadata:attribute",
			MDRPI:  "urn:oasis:names:tc:SAML:metadata:rpi",

			// EntityAttributes: EntityAttributes{
			// 	XMLName: xml.Name{
			// 		Local: "mdattr:EntityAttributes",
			// 	},

			// 	SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
			// 	EntityAttributes: []EntityAttribute{
			// 		EntityAttribute{
			// 			XMLName: xml.Name{
			// 				Local: "saml:Attribute",
			// 			},
			// 			Name:           "https://idm.utsystem.edu/entity-category",
			// 			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			// 			AttributeValue: "---TODO---",
			// 		},
			// 	},
			// },
		},
		SPSSODescriptor: structs.SPSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			SigningKeyDescriptor: structs.KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use: "signing",
				KeyInfo: structs.KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: structs.X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: structs.X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Cert: s.PublicCert(),
						},
					},
				},
			},
			EncryptionKeyDescriptor: structs.KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use: "encryption",
				KeyInfo: structs.KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: structs.X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: structs.X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Cert: s.PublicCert(),
						},
					},
				},
			},
			// SingleLogoutService{
			// 	XMLName: xml.Name{
			// 		Local: "md:SingleLogoutService",
			// 	},
			// 	Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			// 	Location: "---TODO---",
			// },
			AssertionConsumerServices: []structs.AssertionConsumerService{
				structs.AssertionConsumerService{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: s.AssertionConsumerServiceURL,
					Index:    "0",
				},
				structs.AssertionConsumerService{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
					Location: s.AssertionConsumerServiceURL,
					Index:    "1",
				},
			},
		},
	}
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}

	newMetadata := fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b)
	return string(newMetadata), nil
}
