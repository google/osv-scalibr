package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	var response struct {
		Ok    bool   `json:"ok"`
		Error string `json:"error"`
	}
	err := json.Unmarshal(
		[]byte("{\"ok\":true,\"app_name\":\"Demo App\",\"app_id\":\"A09GDGLM2BE\"}"),
		&response)
	fmt.Println("failed to parse JSON response: %w", err)
}
