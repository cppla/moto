package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

var (
	configTopLevelFields = stringSet("log", "metrics", "rules")
	configLogFields      = stringSet("level", "path", "version", "date")
	configMetricsFields  = stringSet("enabled", "listen")
	configRuleFields     = stringSet(
		"name", "listen", "mode", "prewarm", "targets", "timeout",
		"blacklist", "allowlist", "maxConnections", "maxConnectionsPerIP",
		"healthCheck", "proxyProtocol",
	)
	configTargetFields = stringSet("regexp", "address", "serverNames", "alpn")
	configHealthFields = stringSet(
		"type", "interval", "timeout", "failureThreshold", "successThreshold",
		"path", "statusMin", "statusMax",
	)
	configProxyFields = stringSet("accept", "trustedCIDRs", "send")
)

func stringSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

// validateStrictConfigJSON closes two encoding/json compatibility gaps that
// are unsafe for configuration: duplicate keys (last value wins) and
// case-insensitive struct-field matching. It runs before typed decoding.
func validateStrictConfigJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkUniqueJSONValue(decoder, "$", 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}

	root, err := decodeJSONObject(data, "$")
	if err != nil {
		return err
	}
	if err := validateObjectFields("$", root, configTopLevelFields); err != nil {
		return err
	}
	if raw, ok := root["log"]; ok {
		object, objectErr := decodeJSONObject(raw, "$.log")
		if objectErr != nil {
			return objectErr
		}
		if err := validateObjectFields("$.log", object, configLogFields); err != nil {
			return err
		}
	}
	if raw, ok := root["metrics"]; ok {
		object, objectErr := decodeJSONObject(raw, "$.metrics")
		if objectErr != nil {
			return objectErr
		}
		if err := validateObjectFields("$.metrics", object, configMetricsFields); err != nil {
			return err
		}
	}
	rawRules, ok := root["rules"]
	if !ok {
		return nil
	}
	var rules []json.RawMessage
	if err := json.Unmarshal(rawRules, &rules); err != nil {
		return fmt.Errorf("$.rules must be an array: %w", err)
	}
	for ruleIndex, rawRule := range rules {
		rulePath := fmt.Sprintf("$.rules[%d]", ruleIndex)
		rule, err := decodeJSONObject(rawRule, rulePath)
		if err != nil {
			return err
		}
		if err := validateObjectFields(rulePath, rule, configRuleFields); err != nil {
			return err
		}
		if raw, exists := rule["healthCheck"]; exists && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			object, objectErr := decodeJSONObject(raw, rulePath+".healthCheck")
			if objectErr != nil {
				return objectErr
			}
			if err := validateObjectFields(rulePath+".healthCheck", object, configHealthFields); err != nil {
				return err
			}
		}
		if raw, exists := rule["proxyProtocol"]; exists && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			object, objectErr := decodeJSONObject(raw, rulePath+".proxyProtocol")
			if objectErr != nil {
				return objectErr
			}
			if err := validateObjectFields(rulePath+".proxyProtocol", object, configProxyFields); err != nil {
				return err
			}
		}
		rawTargets, exists := rule["targets"]
		if !exists {
			continue
		}
		var targets []json.RawMessage
		if err := json.Unmarshal(rawTargets, &targets); err != nil {
			return fmt.Errorf("%s.targets must be an array: %w", rulePath, err)
		}
		for targetIndex, rawTarget := range targets {
			targetPath := fmt.Sprintf("%s.targets[%d]", rulePath, targetIndex)
			target, err := decodeJSONObject(rawTarget, targetPath)
			if err != nil {
				return err
			}
			if err := validateObjectFields(targetPath, target, configTargetFields); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkUniqueJSONValue(decoder *json.Decoder, path string, depth int) error {
	if depth > 64 {
		return fmt.Errorf("%s: JSON nesting exceeds 64 levels", path)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s: object key is not a string", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%s: duplicate field %q", path, key)
			}
			seen[key] = struct{}{}
			if err := walkUniqueJSONValue(decoder, path+"."+key, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		index := 0
		for decoder.More() {
			if err := walkUniqueJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index), depth+1); err != nil {
				return err
			}
			index++
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("%s: unexpected JSON delimiter %q", path, delimiter)
	}
}

func decodeJSONObject(data []byte, path string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, fmt.Errorf("%s must be an object: %w", path, err)
	}
	if object == nil {
		return nil, fmt.Errorf("%s must be an object", path)
	}
	return object, nil
}

func validateObjectFields(path string, object map[string]json.RawMessage, allowed map[string]struct{}) error {
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%s: unknown or non-canonical field %q", path, key)
		}
	}
	return nil
}
