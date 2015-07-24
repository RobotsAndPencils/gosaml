package structs

import "encoding/xml"

// <md:EntityDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://ssoproxy.utsystem.edu/simplesaml/module.php/saml/sp/metadata.php/default-sp">
type EntityDescriptor struct {
	XMLName  xml.Name
	DS       string `xml:"xmlns:ds,attr"`
	XMLNS    string `xml:"xmlns,attr"`
	MD       string `xml:"xmlns:md,attr"`
	EntityId string `xml:"entityID,attr"`

	Extensions      Extensions      `xml:"Extensions"`
	SPSSODescriptor SPSSODescriptor `xml:"SPSSODescriptor"`
}

type Extensions struct {
	XMLName xml.Name
	Alg     string `xml:"xmlns:alg,attr"`
	MDAttr  string `xml:"xmlns:mdattr,attr"`
	MDRPI   string `xml:"xmlns:mdrpi,attr"`

	EntityAttributes string `xml:"EntityAttributes"`
}

type SPSSODescriptor struct {
	XMLName                    xml.Name
	ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr"`
	SigningKeyDescriptor       KeyDescriptor
	EncryptionKeyDescriptor    KeyDescriptor
	// SingleLogoutService        SingleLogoutService `xml:"SingleLogoutService"`
	AssertionConsumerServices []AssertionConsumerService
}

type EntityAttributes struct {
	XMLName xml.Name
	SAML    string `xml:"xmlns:saml,attr"`

	EntityAttributes []Attribute `xml:"Attribute"` // should be array??
}

type SPSSODescriptors struct {
}

type KeyDescriptor struct {
	XMLName xml.Name
	Use     string  `xml:"use,attr"`
	KeyInfo KeyInfo `xml:"KeyInfo"`
}

type SingleLogoutService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type AssertionConsumerService struct {
	XMLName  xml.Name
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    string `xml:"index,attr"`
}
