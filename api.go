package main

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

// against "unused imports"
var _ time.Time
var _ xml.Name

type GetFields struct {
	XMLName           xml.Name         `xml:"dyn:getFields"`
	AccountId         string           `xml:"accountId,omitempty"`
	Password          string           `xml:"password,omitempty"`
	VerificationId    string           `xml:"verificationId,omitempty"`
	VerificationToken string           `xml:"verificationToken,omitempty"`
	SourceId          string           `xml:"sourceId,omitempty"`
	ExtraData         []*NameValuePair `xml:"extraData,omitempty"`
}

type NameValuePair struct {
	XMLName xml.Name

	Name  string `xml:"name,omitempty" json:"name"`
	Value string `xml:"value,omitempty" json:"value`
}

type GetFieldsResponse struct {
	XMLName xml.Name

	Return_ *CurrentStatusV3 `xml:"return,omitempty"`
}

type CurrentStatusV3 struct {
	XMLName xml.Name

	CheckResult         *LastCheckResultV3     `xml:"checkResult,omitempty"`
	RegistrationDetails *RegistrationDetailsV3 `xml:"registrationDetails,omitempty"`
	SourceFields        *SourceFields          `xml:"sourceFields,omitempty"`
	SourceList          *SourceList            `xml:"sourceList,omitempty"`
	VerificationResult  *VerificationResult    `xml:"verificationResult,omitempty"`
	VerificationToken   string                 `xml:"verificationToken,omitempty"`
}

type LastCheckResultV3 struct {
	State        string `xml:"state,omitempty"`
	StillWorking bool   `xml:"stillWorking,omitempty"`
}

type RegistrationDetailsV3 struct {
	CurrentResidentialAddress  *Address         `xml:"currentResidentialAddress,omitempty"`
	DateCreated                string           `xml:"dateCreated,omitempty"`
	Dob                        *DateOfBirth     `xml:"dob,omitempty"`
	Email                      string           `xml:"email,omitempty"`
	ExtraData                  []*NameValuePair `xml:"extraData,omitempty"`
	HomePhone                  string           `xml:"homePhone,omitempty"`
	MobilePhone                string           `xml:"mobilePhone,omitempty"`
	Name                       *Name            `xml:"name,omitempty"`
	PreviousResidentialAddress *Address         `xml:"previousResidentialAddress,omitempty"`
	WorkPhone                  string           `xml:"workPhone,omitempty"`
}

type Address struct {
	Alley                   string `xml:"alley,omitempty"`
	AmalgamatedMunicipality string `xml:"amalgamatedMunicipality,omitempty"`
	Area                    string `xml:"area,omitempty"`
	Avenue                  string `xml:"avenue,omitempty"`
	Block                   string `xml:"block,omitempty"`
	Canton                  string `xml:"canton,omitempty"`
	Chome                   string `xml:"chome,omitempty"`
	City                    string `xml:"city,omitempty"`
	Country                 string `xml:"country,omitempty"`
	County                  string `xml:"county,omitempty"`
	DeliveryNumber          string `xml:"deliveryNumber,omitempty"`
	Department              string `xml:"department,omitempty"`
	Direction               string `xml:"direction,omitempty"`
	DispatchingInformation  string `xml:"dispatchingInformation,omitempty"`
	District                string `xml:"district,omitempty"`
	DivisionFive            string `xml:"divisionFive,omitempty"`
	DivisionFour            string `xml:"divisionFour,omitempty"`
	DivisionOne             string `xml:"divisionOne,omitempty"`
	DivisionThree           string `xml:"divisionThree,omitempty"`
	DivisionTwo             string `xml:"divisionTwo,omitempty"`
	FlatNumber              string `xml:"flatNumber,omitempty"`
	Level                   string `xml:"level,omitempty"`
	Locality                string `xml:"locality,omitempty"`
	Location                string `xml:"location,omitempty"`
	MailCentre              string `xml:"mailCentre,omitempty"`
	Municipality            string `xml:"municipality,omitempty"`
	Neighbourhood           string `xml:"neighbourhood,omitempty"`
	Organisation            string `xml:"organisation,omitempty"`
	Parish                  string `xml:"parish,omitempty"`
	PersonName              string `xml:"personName,omitempty"`
	PoBox                   string `xml:"poBox,omitempty"`
	Postcode                string `xml:"postcode,omitempty"`
	Prefecture              string `xml:"prefecture,omitempty"`
	PropertyName            string `xml:"propertyName,omitempty"`
	Province                string `xml:"province,omitempty"`
	Quarter                 string `xml:"quarter,omitempty"`
	Region                  string `xml:"region,omitempty"`
	RuralArea               string `xml:"ruralArea,omitempty"`
	RuralLocality           string `xml:"ruralLocality,omitempty"`
	Sector                  string `xml:"sector,omitempty"`
	SectorNumber            string `xml:"sectorNumber,omitempty"`
	State                   string `xml:"state,omitempty"`
	StreetName              string `xml:"streetName,omitempty"`
	StreetNumber            string `xml:"streetNumber,omitempty"`
	StreetType              string `xml:"streetType,omitempty"`
	Subdistrict             string `xml:"subdistrict,omitempty"`
	Subregion               string `xml:"subregion,omitempty"`
	Suburb                  string `xml:"suburb,omitempty"`
	Town                    string `xml:"town,omitempty"`
	TownCity                string `xml:"townCity,omitempty"`
	Township                string `xml:"township,omitempty"`
	UrbanLocality           string `xml:"urbanLocality,omitempty"`
	Village                 string `xml:"village,omitempty"`
}

type DateOfBirth struct {
	Day   int32 `xml:"day,omitempty"`
	Month int32 `xml:"month,omitempty"`
	Year  int32 `xml:"year,omitempty"`
}

type Name struct {
	GivenName   string `xml:"givenName,omitempty"`
	Honorific   string `xml:"honorific,omitempty"`
	MiddleNames string `xml:"middleNames,omitempty"`
	Surname     string `xml:"surname,omitempty"`
}

type SourceFields struct {
	XMLName xml.Name

	FieldList *FieldList `xml:"fieldList,omitempty"`
	RawData   string     `xml:"rawData,omitempty"`
}

type FieldList struct {
	XMLName     xml.Name
	SourceField []*Field `xml:"sourceField,omitempty"`
}

type Field struct {
	XMLName xml.Name

	Attribute  []*NameValuePair `xml:"attribute,omitempty"`
	Label      string           `xml:"label,omitempty"`
	Name       string           `xml:"name,omitempty"`
	SelectItem []*NameValuePair `xml:"selectItem,omitempty"`
	Type_      string           `xml:"type,omitempty"`
	Value      string           `xml:"value,omitempty"`
}

type SourceList struct {
	Source []*Source `xml:"source,omitempty"`
}

type Source struct {
	XMLName xml.Name

	Attributes    []*NameValuePair `xml:"attributes,omitempty"`
	Available     bool             `xml:"available,omitempty"`
	Name          string           `xml:"name,omitempty"`
	NotRequired   bool             `xml:"notRequired,omitempty"`
	OneSourceLeft bool             `xml:"oneSourceLeft,omitempty"`
	Order         int32            `xml:"order,omitempty"`
	Passed        bool             `xml:"passed,omitempty"`
	State         string           `xml:"state,omitempty"`
	Version       int32            `xml:"version,omitempty"`
}

type VerificationResult struct {
	XMLName xml.Name

	DateVerified              string              `xml:"dateVerified,omitempty"`
	IndividualResult          []*IndividualResult `xml:"individualResult,omitempty"`
	Mode                      string              `xml:"mode,omitempty"`
	OverallVerificationStatus string              `xml:"overallVerificationStatus,omitempty"`
	RuleId                    string              `xml:"ruleId,omitempty"`
	VerificationId            string              `xml:"verificationId,omitempty"`
}

type IndividualResult struct {
	XMLName xml.Name

	DateCreated       string           `xml:"dateCreated,omitempty"`
	DateVerified      string           `xml:"dateVerified,omitempty"`
	DocumentRegion    string           `xml:"documentRegion,omitempty"`
	DocumentSubRegion string           `xml:"documentSubRegion,omitempty"`
	DocumentType      string           `xml:"documentType,omitempty"`
	ExtraData         []*NameValuePair `xml:"extraData,omitempty"`
	FaceMatchScore    string           `xml:"faceMatchScore,omitempty"`
	FieldResult       []*FieldResult   `xml:"fieldResult,omitempty"`
	IndividualResult  []*CheckResult   `xml:"individualResult,omitempty"`
	Method            string           `xml:"method,omitempty"`
	Mode              string           `xml:"mode,omitempty"`
	Name              string           `xml:"name,omitempty"`
	PostOfficeData    *PostOfficeData  `xml:"postOfficeData,omitempty"`
	State             string           `xml:"state,omitempty"`
}
type CheckResult struct {
	XMLName xml.Name

	DateCreated       string           `xml:"dateCreated,omitempty"`
	DateVerified      string           `xml:"dateVerified,omitempty"`
	DocumentRegion    string           `xml:"documentRegion,omitempty"`
	DocumentSubRegion string           `xml:"documentSubRegion,omitempty"`
	DocumentType      string           `xml:"documentType,omitempty"`
	ExtraData         []*NameValuePair `xml:"extraData,omitempty"`
	FaceMatchScore    string           `xml:"faceMatchScore,omitempty"`
	FieldResult       []*FieldResult   `xml:"fieldResult,omitempty"`
	IndividualResult  []*CheckResult   `xml:"individualResult,omitempty"`
	Method            string           `xml:"method,omitempty"`
	Mode              string           `xml:"mode,omitempty"`
	Name              string           `xml:"name,omitempty"`
	PostOfficeData    *PostOfficeData  `xml:"postOfficeData,omitempty"`
	State             string           `xml:"state,omitempty"`
}

type FieldResult struct {
	XMLName xml.Name

	AddressType       string           `xml:"addressType,omitempty"`
	ChangedValue      string           `xml:"changedValue,omitempty"`
	Data              string           `xml:"data,omitempty"`
	ExtraData         []*NameValuePair `xml:"extraData,omitempty"`
	ExtractedValue    string           `xml:"extractedValue,omitempty"`
	Format            string           `xml:"format,omitempty"`
	MasterRecordValue string           `xml:"masterRecordValue,omitempty"`
	Name              string           `xml:"name,omitempty"`
	Status            string           `xml:"status,omitempty"`
	Value             string           `xml:"value,omitempty"`
}

type PostOfficeData struct {
	XMLName xml.Name

	CustomerId string              `xml:"customerId,omitempty"`
	Documents  string              `xml:"documents,omitempty"`
	Header     *DetailRecordHeader `xml:"header,omitempty"`
	PoFileName string              `xml:"poFileName,omitempty"`
	Records    []*DocumentRecord   `xml:"records,omitempty"`
}

type DetailRecordHeader struct {
	Amount                   string `xml:"amount,omitempty"`
	ChannelId                string `xml:"channelId,omitempty"`
	Date                     string `xml:"date,omitempty"`
	DateOfBirth              string `xml:"dateOfBirth,omitempty"`
	Filler                   string `xml:"filler,omitempty"`
	FormVersion              string `xml:"formVersion,omitempty"`
	GivenName                string `xml:"givenName,omitempty"`
	Id                       int64  `xml:"id,omitempty"`
	IdWizardRefNo            string `xml:"idWizardRefNo,omitempty"`
	PaymentMethod            string `xml:"paymentMethod,omitempty"`
	PhoneNo                  string `xml:"phoneNo,omitempty"`
	PostOfficeName           string `xml:"postOfficeName,omitempty"`
	RecordNo                 string `xml:"recordNo,omitempty"`
	RecordType               string `xml:"recordType,omitempty"`
	ReferenceNo              string `xml:"referenceNo,omitempty"`
	Surname                  string `xml:"surname,omitempty"`
	TotalNumberOfIdDocuments string `xml:"totalNumberOfIdDocuments,omitempty"`
	TypeCode                 string `xml:"typeCode,omitempty"`
	UniqueReferenceNo        string `xml:"uniqueReferenceNo,omitempty"`
}

type DocumentRecord struct {
	Amount                        string `xml:"amount,omitempty"`
	Comments                      string `xml:"comments,omitempty"`
	CountryOfIssue                string `xml:"countryOfIssue,omitempty"`
	DateOfBirthMatchesForm        string `xml:"dateOfBirthMatchesForm,omitempty"`
	DocumentExpiryDate            string `xml:"documentExpiryDate,omitempty"`
	DocumentName                  string `xml:"documentName,omitempty"`
	DocumentNumber                string `xml:"documentNumber,omitempty"`
	Filler                        string `xml:"filler,omitempty"`
	Id                            int64  `xml:"id,omitempty"`
	IdDocumentType                string `xml:"idDocumentType,omitempty"`
	IdWizardRefNo                 string `xml:"idWizardRefNo,omitempty"`
	IssuedBy                      string `xml:"issuedBy,omitempty"`
	Issuedate                     string `xml:"issuedate,omitempty"`
	NameMatchesform               string `xml:"nameMatchesform,omitempty"`
	PhotoMatch                    string `xml:"photoMatch,omitempty"`
	RecordNo                      string `xml:"recordNo,omitempty"`
	RecordType                    string `xml:"recordType,omitempty"`
	ReferenceNo                   string `xml:"referenceNo,omitempty"`
	ResidentialAddressMatchesForm string `xml:"residentialAddressMatchesForm,omitempty"`
	StateOrTerritoryOfIssue       string `xml:"stateOrTerritoryOfIssue,omitempty"`
	UtilityAccountIssuer          string `xml:"utilityAccountIssuer,omitempty"`
	UtilityAccountType            string `xml:"utilityAccountType,omitempty"`
}

type Fault struct {
	Code    string `xml:"code,omitempty"`
	Details string `xml:"details,omitempty"`
}

type SetFields struct {
	AccountId         string           `xml:"accountId,omitempty"`
	Password          string           `xml:"password,omitempty"`
	VerificationId    string           `xml:"verificationId,omitempty"`
	VerificationToken string           `xml:"verificationToken,omitempty"`
	SourceId          string           `xml:"sourceId,omitempty"`
	InputFields       *InputFields     `xml:"inputFields,omitempty"`
	ExtraData         []*NameValuePair `xml:"extraData,omitempty"`
}

type InputFields struct {
	XMLName xml.Name

	Input []*NameValuePair `xml:"input,omitempty"`
}

type SetFieldsResponse struct {
	XMLName xml.Name

	Return *CurrentStatusV3 `xml:"return,omitempty"`
}

type RegisterVerification struct {
	XMLName xml.Name `xml:"dyn:registerVerification"`

	AccountId                 string   `xml:"accountId,omitempty"`
	Password                  string   `xml:"password,omitempty"`
	VerificationId            string   `xml:"verificationId,omitempty"`
	RuleId                    string   `xml:"ruleId,omitempty"`
	Name                      *Name    `xml:"name,omitempty"`
	Email                     string   `xml:"email,omitempty"`
	CurrentResidentialAddress *Address `xml:"currentResidentialAddress,omitempty"`

	Dob                       *DateOfBirth     `xml:"dob,omitempty"`
	HomePhone                 string           `xml:"homePhone,omitempty"`
	WorkPhone                 string           `xml:"workPhone,omitempty"`
	MobilePhone               string           `xml:"mobilePhone,omitempty"`
	DeviceIDData              string           `xml:"deviceIDData,omitempty"`
	GenerateVerificationToken bool             `xml:"generateVerificationToken,omitempty"`
	ExtraData                 []*NameValuePair `xml:"extraData,omitempty"`
}

type RegisterVerificationResponse struct {
	Return *CurrentStatusV3 `xml:"return,omitempty"`
}

type GetVerificationResult struct {
	XMLName xml.Name

	AccountId         string           `xml:"accountId,omitempty"`
	Password          string           `xml:"password,omitempty"`
	VerificationId    string           `xml:"verificationId,omitempty"`
	VerificationToken string           `xml:"verificationToken,omitempty"`
	ExtraData         []*NameValuePair `xml:"extraData,omitempty"`
}

type GetVerificationResultResponse struct {
	XMLName xml.Name

	Return_ *CurrentStatusV3 `xml:"return,omitempty"`
}

type ExpireToken struct {
	XMLName xml.Name

	AccountId         string           `xml:"accountId,omitempty"`
	Password          string           `xml:"password,omitempty"`
	VerificationToken string           `xml:"verificationToken,omitempty"`
	ExtraData         []*NameValuePair `xml:"extraData,omitempty"`
}

type ExpireTokenResponse struct {
	XMLName xml.Name
}

type GetSources struct {
	XMLName           xml.Name         `xml:"dyn:getSources"`
	AccountId         string           `xml:"accountId,omitempty"`
	Password          string           `xml:"password,omitempty"`
	VerificationId    string           `xml:"verificationId,omitempty"`
	VerificationToken string           `xml:"verificationToken,omitempty"`
	ExtraData         []*NameValuePair `xml:"extraData,omitempty"`
}

type GetSourcesResponse struct {
	Return *CurrentStatusV3 `xml:"return,omitempty"`
}

type GetVerificationToken struct {
	XMLName xml.Name

	AccountId      string           `xml:"accountId,omitempty"`
	Password       string           `xml:"password,omitempty"`
	VerificationId string           `xml:"verificationId,omitempty"`
	ExtraData      []*NameValuePair `xml:"extraData,omitempty"`
}

type GetVerificationTokenResponse struct {
	XMLName xml.Name

	Return_ string `xml:"return,omitempty"`
}

type DynamicFormsServiceV3 struct {
	client *SOAPClient
}

func NewDynamicFormsServiceV3(url string, tls bool, auth *BasicAuth) *DynamicFormsServiceV3 {
	if url == "" {
		url = ""
	}
	client := NewSOAPClient(url, tls, auth)

	return &DynamicFormsServiceV3{
		client: client,
	}
}

func (service *DynamicFormsServiceV3) GetFields(request *GetFields) (*CreateGetFieldEnvelope, error) {
	response := new(GetFieldsResponse)
	soapResp, err := service.client.Call("getFields", request, response)
	// log.Println(err)
	if err != nil {
		return nil, err
	}

	log.Println(soapResp)
	var createEnv CreateGetFieldEnvelope
	marshalErr := xml.Unmarshal([]byte(soapResp), &createEnv)

	if marshalErr != nil {
		fmt.Println(marshalErr)
		return nil, marshalErr
	}

	return &createEnv, nil
}

func (service *DynamicFormsServiceV3) GetSources(request *GetSources) (*CreateGetSourceEnvelope, error) {
	response := new(GetSourcesResponse)
	soapResp, err := service.client.Call("getSources", request, response)
	log.Println(err)
	if err != nil {
		return nil, err
	}

	log.Println(soapResp)
	var createEnv CreateGetSourceEnvelope
	marshalErr := xml.Unmarshal([]byte(soapResp), &createEnv)

	if marshalErr != nil {
		fmt.Println(marshalErr)
		return nil, marshalErr
	}

	return &createEnv, nil
}
func (service *DynamicFormsServiceV3) RegisterVerification(request *RegisterVerification) (*CreateRegisterVerificationEnvelope, error) {
	response := new(RegisterVerificationResponse)
	soapResp, err := service.client.Call("registerVerification", request, response)

	if err != nil {
		return nil, err
	}
	// log.Println(soapResp)
	var createEnv CreateRegisterVerificationEnvelope
	marshalErr := xml.Unmarshal([]byte(soapResp), &createEnv)

	// log.Println(createEnv.CreateBody.RegisterVerificationResponse.Return.VerificationResult.VerificationId)

	if marshalErr != nil {
		fmt.Println(marshalErr)
		return nil, marshalErr
	}

	return &createEnv, nil
}

func (service *DynamicFormsServiceV3) SetFields(request *SetFields) (*CreateSetFieldEnvelope, error) {
	response := new(SetFieldsResponse)
	soapResp, err := service.client.Call("setFields", request, response)
	if err != nil {
		return nil, err
	}

	var createEnv CreateSetFieldEnvelope
	marshalErr := xml.Unmarshal([]byte(soapResp), &createEnv)

	if marshalErr != nil {
		fmt.Println(marshalErr)
		return nil, marshalErr
	}

	return &createEnv, nil
}

var timeout = time.Duration(30 * time.Second)

func dialTimeout(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

type CreateRegisterVerificationEnvelope struct {
	CreateBody createRegisterVerificationBody `xml:"Body"`
}

type createRegisterVerificationBody struct {
	Fault                        *SOAPFault                   `xml:"Fault,omitempty"`
	RegisterVerificationResponse RegisterVerificationResponse `xml:"registerVerificationResponse"`
}
type CreateGetSourceEnvelope struct {
	CreateBody createGetSourceBody `xml:"Body"`
}

type createGetSourceBody struct {
	Fault              *SOAPFault         `xml:"Fault,omitempty"`
	GetSourcesResponse GetSourcesResponse `xml:"getSourcesResponse"`
}
type CreateGetFieldEnvelope struct {
	CreateBody createGetFieldBody `xml:"Body"`
}

type createGetFieldBody struct {
	Fault             *SOAPFault        `xml:"Fault,omitempty"`
	GetFieldsResponse GetFieldsResponse `xml:"getFieldsResponse"`
}

type CreateSetFieldEnvelope struct {
	CreateBody createSetFieldBody `xml:"Body"`
}

type createSetFieldBody struct {
	Fault             *SOAPFault        `xml:"Fault,omitempty"`
	SetFieldsResponse SetFieldsResponse `xml:"setFieldsResponse"`
}

//Response from Vixverify is a bit different. create another struct
type SOAPRegisterVerificationResponseEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    SOAPRegisterVerificationResponseBody
}
type SOAPRegisterVerificationResponseBody struct {
	XMLName     xml.Name    `xml:"Body"`
	Fault       *SOAPFault  `xml:"Fault,omitempty"`
	RegResponse interface{} `xml:"registerVerificationResponse"`
}

type SOAPEnvelope struct {
	XMLName xml.Name `xml:"soapenv:Envelope"`
	NS      string   `xml:"xmlns:soapenv,attr"`
	DYN     string   `xml:"xmlns:dyn,attr"` //hardcode attr to match Vixverify
	Body    SOAPBody
}

type SOAPHeader struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`

	Header interface{}
}

type SOAPBody struct {
	XMLName xml.Name `xml:"soapenv:Body"`

	Fault   *SOAPFault  `xmlFault",omitempty"`
	Content interface{} `xml:",omitempty"`
}

type SOAPFault struct {
	XMLName xml.Name `xml:"Fault"`

	Code   string `xml:"faultcode,omitempty"`
	String string `xml:"faultstring,omitempty"`
	Actor  string `xml:"faultactor,omitempty"`
	Detail string `xml:"detail,omitempty"`
}

type BasicAuth struct {
	Login    string
	Password string
}

type SOAPClient struct {
	url  string
	tls  bool
	auth *BasicAuth
}

func (b *SOAPBody) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}

	var (
		token    xml.Token
		err      error
		consumed bool
	)

Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}

		if token == nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError("Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && se.Name.Local == "Fault" {
				b.Fault = &SOAPFault{}
				b.Content = nil

				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}

				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}

				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}

	return nil
}

func (f *SOAPFault) Error() string {
	return f.String
}

func NewSOAPClient(url string, tls bool, auth *BasicAuth) *SOAPClient {
	return &SOAPClient{
		url:  url,
		tls:  tls,
		auth: auth,
	}
}

func (s *SOAPClient) Call(soapAction string, request, response interface{}) (string, error) {
	envelope := SOAPEnvelope{
		NS:  "http://schemas.xmlsoap.org/soap/envelope/",
		DYN: "http://dynamicform.services.registrations.edentiti.com/", //hardcode attr to match Vixverify
	}

	envelope.Body.Content = request
	buffer := new(bytes.Buffer)

	encoder := xml.NewEncoder(buffer)
	encoder.Indent("", "  ")

	if err := encoder.Encode(envelope); err != nil {
		fmt.Printf("Err: %v\n", err)
		return "", err
	}

	if err := encoder.Flush(); err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", s.url, buffer)
	if err != nil {
		return "", err
	}
	if s.auth != nil {
		req.SetBasicAuth(s.auth.Login, s.auth.Password)
	}

	req.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	if soapAction != "" {
		req.Header.Add("SOAPAction", soapAction)
	}

	req.Close = true

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.tls,
		},
		Dial: dialTimeout,
	}

	client := &http.Client{Transport: tr}
	res, err := client.Do(req)

	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	rawbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	if len(rawbody) == 0 {
		log.Println("empty response")
		return "", errors.New("Empty response.")
	}

	return string(rawbody), nil
}
