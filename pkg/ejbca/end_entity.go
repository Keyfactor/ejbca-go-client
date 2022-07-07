package ejbca

import (
	"encoding/json"
	"log"
)

func (c *RESTClient) EndEntitySearch(criteria *EndEntitySearch) (*EndEntitySearchResponse, error) {
	log.Printf("[INFO] Searching EJBCA for end entities with criteria %x", criteria)

	requestConfig := &request{
		Method:   "POST",
		Endpoint: "v1/endentity/search",
		Payload:  criteria,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &EndEntitySearchResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	return jsonResp, nil
}

func (c *RESTClient) GetV1EndEntityStatus() (*V1EndEntityStatus, error) {
	log.Println("[INFO] Getting EJBCA V1 End Entity Endpoint Status")

	requestConfig := &request{
		Method:   "GET",
		Endpoint: "v1/endentity/status",
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &V1EndEntityStatus{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil

}
