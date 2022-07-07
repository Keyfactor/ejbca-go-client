package ejbca

import (
	"log"
	"testing"
)

func TestClient_EndEntitySearch(t *testing.T) {
	ejbcaTestPreCheck(t)

	criteria := &EndEntitySearch{Search{
		MaxNumberOfResults: 100,
		Criteria: []Criteria{
			{
				Property:  "STATUS",
				Value:     "New",
				Operation: "EQUAL"},
		},
	}}

	resp, err := client.EndEntitySearch(criteria)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Found end entities with property %s %s to %s:\n %+v", criteria.Criteria[0].Property, criteria.Criteria[0].Operation, criteria.Criteria[0].Value, *resp)
}

func TestClient_GetV1EndEntityStatus(t *testing.T) {
	ejbcaTestPreCheck(t)

	status, err := client.GetV1EndEntityStatus()
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("End entity endpoint has status %s, version %s, and revision %s", status.Status, status.Version, status.Revision)
}
