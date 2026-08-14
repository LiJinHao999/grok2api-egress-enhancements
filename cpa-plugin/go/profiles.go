package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	profileThroughput     = "throughput"
	profileQualityMarker  = "quality-marker"
	matchContains         = "contains"
	matchLastLine         = "last_line"
	matchRegex            = "regex"
	reasonMarkerMissing   = "expected_marker_missing"
	maxProbeContentRunes  = 32 * 1024
	maxCustomProfiles     = 32
)

// ProbeProfile is a reusable active-probe recipe: prompt + expected marker.
// Built-ins are refreshed from code on load. Custom profiles are operator-owned.
type ProbeProfile struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	BuiltIn         bool    `json:"built_in"`
	Prompt          string  `json:"prompt"`
	ExpectedText    string  `json:"expected_text,omitempty"`
	MatchMode       string  `json:"match_mode"`
	RequireThinking bool    `json:"require_thinking,omitempty"`
	Model           string  `json:"model,omitempty"`
	MaxOutputTokens int     `json:"max_output_tokens,omitempty"`
	Temperature     float64 `json:"temperature,omitempty"`
	UpdatedAt       float64 `json:"updated_at,omitempty"`
}

func builtinProfiles() []ProbeProfile {
	return []ProbeProfile{
		{
			ID:          profileThroughput,
			Name:        "吞吐基线",
			BuiltIn:     true,
			Prompt:      "Write a detailed technical explanation of how TCP slow start works, at least 12 sentences, plain text only.",
			MatchMode:   matchContains,
			Temperature: 0.7,
		},
		{
			ID:           profileQualityMarker,
			Name:         "预期标记",
			BuiltIn:      true,
			Prompt:       "先用三点总结为什么天空呈蓝色，最后一行只输出 QUALITY_OK。",
			ExpectedText: "QUALITY_OK",
			MatchMode:    matchLastLine,
			Temperature:  0,
		},
	}
}

func defaultProbeProfileID() string {
	return profileThroughput
}

func normalizeMatchMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case matchLastLine, "last-line", "lastline":
		return matchLastLine
	case matchRegex, "regexp":
		return matchRegex
	default:
		return matchContains
	}
}

func lastNonEmptyLine(text string) string {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line
		}
	}
	return ""
}

func matchExpected(text, expected, mode string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return true
	}
	text = strings.TrimRightFunc(text, unicode.IsSpace)
	switch normalizeMatchMode(mode) {
	case matchLastLine:
		line := lastNonEmptyLine(text)
		if line == "" {
			return false
		}
		if strings.EqualFold(line, expected) {
			return true
		}
		return strings.Contains(line, expected)
	case matchRegex:
		re, err := regexp.Compile(expected)
		if err != nil {
			return false
		}
		return re.MatchString(text)
	default:
		return strings.Contains(text, expected)
	}
}

func validateProbeProfile(p *ProbeProfile, creating bool) error {
	if p == nil {
		return fmt.Errorf("方案不能为空")
	}
	p.Name = strings.TrimSpace(p.Name)
	p.Prompt = strings.TrimSpace(p.Prompt)
	p.ExpectedText = strings.TrimSpace(p.ExpectedText)
	p.Model = strings.TrimSpace(p.Model)
	p.MatchMode = normalizeMatchMode(p.MatchMode)
	if p.Name == "" {
		return fmt.Errorf("方案名称不能为空")
	}
	if len(p.Name) > 80 {
		return fmt.Errorf("方案名称不能超过 80 个字符")
	}
	if p.Prompt == "" {
		return fmt.Errorf("探测 Prompt 不能为空")
	}
	if len(p.Prompt) > 8000 {
		return fmt.Errorf("探测 Prompt 不能超过 8000 个字符")
	}
	if len(p.ExpectedText) > 400 {
		return fmt.Errorf("预期标记不能超过 400 个字符")
	}
	if p.MatchMode == matchRegex && p.ExpectedText != "" {
		if _, err := regexp.Compile(p.ExpectedText); err != nil {
			return fmt.Errorf("正则预期标记无效: %w", err)
		}
	}
	if p.MaxOutputTokens < 0 || p.MaxOutputTokens > 4096 {
		return fmt.Errorf("方案最大输出需在 0 到 4096 Token 之间")
	}
	if p.Temperature < 0 || p.Temperature > 2 {
		return fmt.Errorf("温度需在 0 到 2 之间")
	}
	if creating && p.BuiltIn {
		return fmt.Errorf("不能新建内置方案")
	}
	return nil
}

func classifyWithProfile(res qualityResult, profile ProbeProfile, pol policyConfig) qualityResult {
	if profile.ExpectedText != "" {
		if !res.ExpectedMatched {
			res.Classification = "hard"
			res.Error = "响应缺少预期标记"
			res.ErrorKind = reasonMarkerMissing
			return res
		}
		// Marker hit is the primary signal. Only apply TPS when the sample
		// is long enough to be a real throughput measurement.
		if res.OutputTokens >= pol.MinOutputTokens && res.TPS > 0 {
			res.Classification = classifyTPS(res.TPS, pol.SoftTPS, pol.HardTPS)
		} else {
			res.Classification = "healthy"
		}
		res.Error = ""
		res.ErrorKind = ""
		return res
	}
	if profile.RequireThinking && !res.HasThinking && (pol.MinOutputTokens <= 0 || res.OutputTokens >= pol.MinOutputTokens) {
		res.Classification = "hard"
		res.Error = "响应缺少 thinking_content（降智）"
		res.ErrorKind = "missing_thinking"
		return res
	}
	res.Classification = classifyQuality(res.TPS, res.OutputTokens, res.HasThinking, pol)
	if res.Classification == "hard" && pol.ThinkingGuard && !res.HasThinking {
		res.Error = "响应缺少 thinking_content（降智）"
	} else {
		res.Error = ""
	}
	res.ErrorKind = ""
	return res
}

func appendCappedRunes(dst *strings.Builder, chunk string, capRunes int) {
	if dst == nil || chunk == "" || capRunes <= 0 {
		return
	}
	remaining := capRunes - utf16ishLen(dst.String())
	if remaining <= 0 {
		return
	}
	runes := []rune(chunk)
	if len(runes) > remaining {
		runes = runes[:remaining]
	}
	dst.WriteString(string(runes))
}

func utf16ishLen(s string) int {
	return len([]rune(s))
}

func nowUnix() float64 {
	return float64(time.Now().Unix())
}
