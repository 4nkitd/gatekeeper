package gatekeeper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

func newParsedProfanityFilter(config *ProfanityFilterConfig) (*parsedProfanityFilter, error) {
	parsed := &parsedProfanityFilter{
		config:        config,
		blockWordsSet: make(map[string]struct{}),
		allowWordsSet: make(map[string]struct{}),
	}

	if len(config.BlockWords) == 0 {
		return nil, fmt.Errorf("ProfanityFilter defined but no blockWords provided")
	}

	for _, word := range config.BlockWords {
		parsed.blockWordsSet[strings.ToLower(word)] = struct{}{}
	}
	for _, word := range config.AllowWords {
		parsed.allowWordsSet[strings.ToLower(word)] = struct{}{}
	}
	return parsed, nil
}

// ProfanityPolicy is a middleware that filters requests based on profane content.
func (gk *Gatekeeper) ProfanityPolicy(next http.Handler) http.Handler {
	if gk.parsedProfanityFilter == nil {
		return next
	}
	p := gk.parsedProfanityFilter.config // Use the original config for flags like CheckQueryParams

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requestBodyCopy []byte // To store body if read

		// 1. Check Query Parameters
		if p.CheckQueryParams {
			if gk.scanValuesForProfanity(r.URL.Query()) {
				gk.blockRequest(w, r, p.BlockedStatusCode, p.BlockedMessage, "Profanity in query parameters")
				return
			}
		}

		// 2. Check Form Fields (application/x-www-form-urlencoded or multipart/form-data)
		// This requires parsing the body or form.
		// Be careful: r.ParseForm and r.ParseMultipartForm read r.Body.
		contentType := r.Header.Get("Content-Type")
		if p.CheckFormFields && contentType != "" {
			mediaType, _, err := mime.ParseMediaType(contentType)
			if err == nil {
				if mediaType == "application/x-www-form-urlencoded" {
					// If body is already read for JSON check, we can't re-parse form.
					// This highlights the order dependency or need for more careful body handling.
					// Assume for now distinct checks. If JSON check is also on, body reading needs care.
					if err := r.ParseForm(); err == nil {
						if gk.scanValuesForProfanity(r.Form) {
							gk.blockRequest(w, r, p.BlockedStatusCode, p.BlockedMessage, "Profanity in form data (urlencoded)")
							return
						}
					}
				} else if mediaType == "multipart/form-data" {
					// Max memory for multipart form: 10MB, can be configurable
					if err := r.ParseMultipartForm(10 << 20); err == nil && r.MultipartForm != nil {
						if gk.scanValuesForProfanity(r.MultipartForm.Value) {
							gk.blockRequest(w, r, p.BlockedStatusCode, p.BlockedMessage, "Profanity in form data (multipart)")
							return
						}
						// Note: File contents are not checked by this.
					}
				}
				// If body was read by form parsing, we need to "restore" it if JSON check is also needed.
				// However, standard library doesn't easily allow this after ParseForm/ParseMultipartForm.
				// This implies we should read body ONCE, then parse based on content type.
				// Let's adjust: Read body first if JSON check is enabled, then try to parse.
			}
		}

		// 3. Check JSON Body
		// This MUST be done carefully as r.Body is an io.ReadCloser.
		if p.CheckJSONBody && strings.HasPrefix(contentType, "application/json") {
			if len(requestBodyCopy) == 0 && r.Body != nil && r.Body != http.NoBody {
				var errRead error
				requestBodyCopy, errRead = io.ReadAll(r.Body)
				r.Body.Close() // Close original body
				if errRead != nil {
					gk.logger.Printf("ProfanityFilter: Error reading request body: %v", errRead)
					// http.Error(w, "Error reading request body", http.StatusInternalServerError)
					// Let it pass? Or block? For now, let it pass but log.
					next.ServeHTTP(w, r) // Pass with original (now empty) body
					return
				}
				// Restore the body so downstream handlers can read it
				r.Body = io.NopCloser(bytes.NewBuffer(requestBodyCopy))
			}

			if len(requestBodyCopy) > 0 {
				var jsonData interface{} // Use interface{} to handle any JSON structure (object, array, value)
				if err := json.Unmarshal(requestBodyCopy, &jsonData); err == nil {
					if gk.scanJSONForProfanity(jsonData) {
						gk.blockRequest(w, r, p.BlockedStatusCode, p.BlockedMessage, "Profanity in JSON body")
						return
					}
				} else {
					gk.logger.Printf("ProfanityFilter: Error unmarshalling JSON body: %v", err)
					// Don't block if JSON is malformed, let app handle it.
				}
			}
		}

		// If body was read and request is passed, ensure r.Body is reset.
		// This is handled above by reassigning r.Body after reading.

		next.ServeHTTP(w, r)
	})
}

func (gk *Gatekeeper) scanValuesForProfanity(values url.Values) bool {
	p := gk.parsedProfanityFilter // Use parsed filter for sets

	for _, vals := range values {
		for _, val := range vals {
			lowerVal := strings.ToLower(val)

			// First check if the entire value is in the allow list
			if _, isAllowed := p.allowWordsSet[lowerVal]; isAllowed {
				continue // Skip this value entirely if it's explicitly allowed
			}

			// Check if any allowed word contains the blocked word and is present in the value
			for profaneWord := range p.blockWordsSet {
				if strings.Contains(lowerVal, profaneWord) {
					// Check if this specific profane word is explicitly allowed
					if _, isDirectlyAllowed := p.allowWordsSet[profaneWord]; isDirectlyAllowed {
						continue
					}

					// Check if any allowed word that contains this profane word is present in the value
					isWordAllowed := false
					for allowedWord := range p.allowWordsSet {
						if strings.Contains(allowedWord, profaneWord) && strings.Contains(lowerVal, allowedWord) {
							isWordAllowed = true
							break
						}
					}

					if !isWordAllowed {
						gk.logger.Printf("Profanity found in value: '%s' (matched: '%s')", val, profaneWord)
						return true
					}
				}
			}
		}
	}
	return false
}

func (gk *Gatekeeper) scanJSONForProfanity(data interface{}) bool {
	p := gk.parsedProfanityFilter // Use parsed filter for sets

	switch v := data.(type) {
	case string:
		lowerVal := strings.ToLower(v)

		// First check if the entire string is in the allow list
		if _, isAllowed := p.allowWordsSet[lowerVal]; isAllowed {
			return false // Skip this string entirely if it's explicitly allowed
		}

		// Check for blocked words within the string
		for profaneWord := range p.blockWordsSet {
			if strings.Contains(lowerVal, profaneWord) {
				// Check if this specific profane word is explicitly allowed
				if _, isDirectlyAllowed := p.allowWordsSet[profaneWord]; isDirectlyAllowed {
					continue
				}

				// Check if any allowed word that contains this profane word is present in the value
				isWordAllowed := false
				for allowedWord := range p.allowWordsSet {
					if strings.Contains(allowedWord, profaneWord) && strings.Contains(lowerVal, allowedWord) {
						isWordAllowed = true
						break
					}
				}

				if !isWordAllowed {
					gk.logger.Printf("Profanity found in JSON string: '%s' (matched: '%s')", v, profaneWord)
					return true
				}
			}
		}
	case map[string]interface{}:
		for _, val := range v {
			if gk.scanJSONForProfanity(val) { // Recurse
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if gk.scanJSONForProfanity(item) { // Recurse
				return true
			}
		}
		// Other types (bool, number, nil) are ignored
	}
	return false
}

func canHaveBody(method string) bool {
	return method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE"
}
