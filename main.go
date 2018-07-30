package main

import (
	"errors"
	"log"
	"os"
)

//sample form which you can accept request from Json
type RegisterVerificationForm struct {
	Country      string `json:"country"`
	State        string `json:"state"`
	StreetName   string `json:"state"`
	StreetNumber string `json:"state"`
	Suburb       string `json:"state"`
	Day          int    `json:"day"`
	Month        int    `json:"month"`
	Year         int    `json:"year"`
	GivenName    string `json:"givenname"`
	Surname      string `json:"surname"`
	Email        string `json:"email"`
	HomePhone    string `json:"homephone"`
	MobilePhone  string `json:"mobilephone"`
	RuleId       string `json:"ruleId"`
}

type VixRequest struct {
	URL string
}

func (vix *VixRequest) init() {
	//should be either
	// https://au.vixverify.com/Registrations-Registrations/DynamicFormsServiceV3?wsdl
	// https://test-au.vixverify.com/Registrations-Registrations/DynamicFormsServiceV3?WSDL
	vix.URL = os.Getenv("SOAPURL")
}

// Sample code on how to call the api
func (vix *VixRequest) RegisterVerificationRequest(form RegisterVerificationForm) (*VerificationResult, error) {
	var defaultRule string
	// this will depends on you setup in your Vixverify setting.
	if len(form.RuleId) < 1 {
		defaultRule = "default"
	} else {
		defaultRule = form.RuleId
	}
	address := Address{
		Country:      form.Country,
		State:        form.State,
		StreetName:   form.StreetName,
		StreetNumber: form.StreetNumber,
		Suburb:       form.Suburb,
	}
	dob := DateOfBirth{
		Day:   int32(form.Day),
		Month: int32(form.Month),
		Year:  int32(form.Year),
	}
	name := Name{
		GivenName: form.GivenName,
		Surname:   form.Surname,
	}
	registerVerification := RegisterVerification{
		CurrentResidentialAddress: &address,
		Dob:                       &dob,
		Email:                     form.Email,
		HomePhone:                 form.HomePhone,
		MobilePhone:               form.MobilePhone,
		Name:                      &name,
		AccountId:                 os.Getenv("AccountId"), //assume you have the account id as env var
		Password:                  os.Getenv("Password"),
		GenerateVerificationToken: true,
		RuleId: defaultRule,
	}
	vix.init()
	soap := NewDynamicFormsServiceV3(vix.URL, true, nil)
	response, err := soap.RegisterVerification(&registerVerification)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if response.CreateBody.Fault != nil {
		return nil, errors.New(response.CreateBody.Fault.Detail)
	}

	return response.CreateBody.RegisterVerificationResponse.Return.VerificationResult, nil
}

func main() {
	//
}
