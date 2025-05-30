package gatekeeper

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProfanityFilter(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	tests := []struct {
		name               string
		config             ProfanityFilterConfig
		requestURL         string
		requestMethod      string
		requestBody        string
		contentType        string
		expectedStatusCode int
		expectBlocked      bool
	}{
		// Query Params Tests
		{
			name: "Query Param - Block Word Present",
			config: ProfanityFilterConfig{
				BlockWords:       []string{"badword"},
				CheckQueryParams: true,
			},
			requestURL:         "/?query=some+badword+here",
			requestMethod:      http.MethodGet,
			expectedStatusCode: http.StatusBadRequest,
			expectBlocked:      true,
		},
		{
			name: "Query Param - No Block Word",
			config: ProfanityFilterConfig{
				BlockWords:       []string{"badword"},
				CheckQueryParams: true,
			},
			requestURL:         "/?query=some+good+stuff",
			requestMethod:      http.MethodGet,
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
		{
			name: "Query Param - CheckQueryParams False",
			config: ProfanityFilterConfig{
				BlockWords:       []string{"badword"},
				CheckQueryParams: false, // Important
			},
			requestURL:         "/?query=some+badword+here",
			requestMethod:      http.MethodGet,
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
		{
			name: "Query Param - Allow Word Present",
			config: ProfanityFilterConfig{
				BlockWords:       []string{"hell"},
				AllowWords:       []string{"hello"}, // "hell" is part of "hello"
				CheckQueryParams: true,
			},
			requestURL:         "/?greeting=hello+world",
			requestMethod:      http.MethodGet,
			expectedStatusCode: http.StatusOK, // Should be allowed because "hello" is whitelisted
			expectBlocked:      false,
		},
		{
			name: "Query Param - Scunthorpe Problem (Allow Word)",
			config: ProfanityFilterConfig{
				BlockWords:       []string{"cunt"},
				AllowWords:       []string{"scunthorpe"}, // Allow the full word "scunthorpe"
				CheckQueryParams: true,
			},
			requestURL:         "/?town=Scunthorpe",
			requestMethod:      http.MethodGet,
			expectedStatusCode: http.StatusOK, // Should be allowed
			expectBlocked:      false,
		},
		{
			name: "Query Param - Block Word Case Insensitive",
			config: ProfanityFilterConfig{
				BlockWords:       []string{"BADWORD"},
				CheckQueryParams: true,
			},
			requestURL:         "/?query=some+badword+here",
			requestMethod:      http.MethodGet,
			expectedStatusCode: http.StatusBadRequest,
			expectBlocked:      true,
		},

		// Form Fields Tests (application/x-www-form-urlencoded)
		{
			name: "Form URLEncoded - Block Word Present",
			config: ProfanityFilterConfig{
				BlockWords:      []string{"profane"},
				CheckFormFields: true,
			},
			requestURL:         "/submit",
			requestMethod:      http.MethodPost,
			requestBody:        "field1=good&field2=contains+profane+word",
			contentType:        "application/x-www-form-urlencoded",
			expectedStatusCode: http.StatusBadRequest,
			expectBlocked:      true,
		},
		{
			name: "Form URLEncoded - CheckFormFields False",
			config: ProfanityFilterConfig{
				BlockWords:      []string{"profane"},
				CheckFormFields: false, // Important
			},
			requestURL:         "/submit",
			requestMethod:      http.MethodPost,
			requestBody:        "field1=good&field2=contains+profane+word",
			contentType:        "application/x-www-form-urlencoded",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},

		// Form Fields Tests (multipart/form-data)
		{
			name: "Form Multipart - Block Word Present",
			config: ProfanityFilterConfig{
				BlockWords:      []string{"dirty"},
				CheckFormFields: true,
			},
			requestURL:    "/upload",
			requestMethod: http.MethodPost,
			// requestBody and contentType will be set dynamically for multipart
			expectedStatusCode: http.StatusBadRequest,
			expectBlocked:      true,
		},

		// JSON Body Tests
		{
			name: "JSON Body - Block Word Present",
			config: ProfanityFilterConfig{
				BlockWords:    []string{"offensive"},
				CheckJSONBody: true,
			},
			requestURL:         "/api/data",
			requestMethod:      http.MethodPost,
			requestBody:        `{"key": "some offensive content"}`,
			contentType:        "application/json",
			expectedStatusCode: http.StatusBadRequest,
			expectBlocked:      true,
		},
		{
			name: "JSON Body - Nested Block Word",
			config: ProfanityFilterConfig{
				BlockWords:    []string{"nasty"},
				CheckJSONBody: true,
			},
			requestURL:         "/api/data",
			requestMethod:      http.MethodPost,
			requestBody:        `{"level1": {"level2": "a nasty phrase"}}`,
			contentType:        "application/json",
			expectedStatusCode: http.StatusBadRequest,
			expectBlocked:      true,
		},
		{
			name: "JSON Body - CheckJSONBody False",
			config: ProfanityFilterConfig{
				BlockWords:    []string{"offensive"},
				CheckJSONBody: false, // Important
			},
			requestURL:         "/api/data",
			requestMethod:      http.MethodPost,
			requestBody:        `{"key": "some offensive content"}`,
			contentType:        "application/json",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
		{
			name: "JSON Body - Allow Word Present",
			config: ProfanityFilterConfig{
				BlockWords:    []string{"ass"},
				AllowWords:    []string{"assistant"},
				CheckJSONBody: true,
			},
			requestURL:         "/api/data",
			requestMethod:      http.MethodPost,
			requestBody:        `{"role": "assistant manager"}`,
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},

		// Combined Checks
		{
			name: "Combined - Query OK, Form Blocked",
			config: ProfanityFilterConfig{
				BlockWords:       []string{"blockedform"},
				CheckQueryParams: true,
				CheckFormFields:  true,
			},
			requestURL:         "/submit?query=clean",
			requestMethod:      http.MethodPost,
			requestBody:        "field=this+is+blockedform",
			contentType:        "application/x-www-form-urlencoded",
			expectedStatusCode: http.StatusBadRequest,
			expectBlocked:      true,
		},
		{
			name: "Combined - Query Blocked, JSON OK (but query checked first)",
			config: ProfanityFilterConfig{
				BlockWords:       []string{"blockedquery"},
				CheckQueryParams: true,
				CheckJSONBody:    true,
			},
			requestURL:         "/api?param=this+is+blockedquery",
			requestMethod:      http.MethodPost,
			requestBody:        `{"data": "clean"}`,
			contentType:        "application/json",
			expectedStatusCode: http.StatusBadRequest,
			expectBlocked:      true,
		},
		{
			name: "No checks enabled",
			config: ProfanityFilterConfig{
				BlockWords: []string{"anything"},
				// All CheckX flags are false by default or explicitly set
				CheckQueryParams: false,
				CheckFormFields:  false,
				CheckJSONBody:    false,
			},
			requestURL:         "/?query=anything",
			requestMethod:      http.MethodPost,
			requestBody:        `{"key": "anything"}`,
			contentType:        "application/json",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gk := &Gatekeeper{
				config: Config{
					ProfanityFilter:        &tt.config,
					DefaultBlockStatusCode: http.StatusForbidden, // General default
				},
				logger: testLogger(t),
			}

			// Replace manual newParsedProfanityFilter with Gatekeeper.New
			initializedGk, err := New(gk.config)
			if err != nil {
				if len(tt.config.BlockWords) > 0 {
					t.Fatalf("Gatekeeper.New failed: %v", err)
				} else if initializedGk.config.ProfanityFilter != nil {
					t.Fatalf("initializedGk.ProfanityFilter should be nil if no block words are provided")
				}
			}

			var req *http.Request
			body := strings.NewReader(tt.requestBody)

			if tt.name == "Form Multipart - Block Word Present" { // Special handling for multipart
				bodyBytes := new(bytes.Buffer)
				writer := multipart.NewWriter(bodyBytes)
				field, _ := writer.CreateFormField("text_field")
				field.Write([]byte("this field contains a dirty word"))
				writer.Close()

				req = httptest.NewRequest(tt.requestMethod, tt.requestURL, bodyBytes)
				req.Header.Set("Content-Type", writer.FormDataContentType())
			} else {
				req = httptest.NewRequest(tt.requestMethod, tt.requestURL, body)
				if tt.contentType != "" {
					req.Header.Set("Content-Type", tt.contentType)
				}
			}

			// If the method is POST/PUT etc. and body is not multipart, parse form for urlencoded
			if (tt.requestMethod == http.MethodPost || tt.requestMethod == http.MethodPut) &&
				strings.Contains(tt.contentType, "application/x-www-form-urlencoded") {
				if err := req.ParseForm(); err != nil {
					t.Fatalf("Failed to parse form: %v", err)
				}
			}

			rr := httptest.NewRecorder()
			handlerToTest := initializedGk.ProfanityPolicy(dummyHandler) // Use initializedGk
			handlerToTest.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatusCode {
				t.Errorf("Expected status code %d, got %d. Body: %s", tt.expectedStatusCode, rr.Code, rr.Body.String())
			}

			if tt.expectBlocked && rr.Body.String() == "OK" {
				t.Errorf("Expected request to be blocked, but it was allowed.")
			}
			if !tt.expectBlocked && rr.Body.String() != "OK" {
				t.Errorf("Expected request to be allowed, but it was blocked. Status: %d, Body: %s", rr.Code, rr.Body.String())
			}
		})
	}
}
