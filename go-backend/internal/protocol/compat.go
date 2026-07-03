package protocol

import (
	"context"
	"fmt"
	"strings"
	"time"

	"chatgpt2api-go-backend/internal/account"
)

func Response(body map[string]any, chat ConversationStreamer, image ImageGenerator, accounts ImageAccountPool) (map[string]any, error) {
	model := firstNonEmpty(clean(body["model"]), "auto")
	prompt := responsePrompt(body["input"], body["instructions"])
	id := "resp_" + newHex(32)
	created := time.Now().Unix()
	if tool := imageTool(body["tools"]); len(tool) > 0 {
		if prompt == "" {
			return nil, fmt.Errorf("input text is required")
		}
		if image == nil || accounts == nil {
			return nil, fmt.Errorf("image generation upstream is not configured")
		}
		if model == "auto" {
			model = "gpt-image-2"
		}
		size := firstNonEmpty(clean(tool["size"]), "1:1")
		finalPrompt := promptWithImageQuality(prompt, clean(tool["quality"]))
		data, err := GenerateImageWithPool(context.Background(), image, accounts, finalPrompt, model, size, "b64_json")
		if err != nil {
			return nil, err
		}
		output := make([]map[string]any, 0, len(data))
		for i, item := range data {
			if b64 := clean(item["b64_json"]); b64 != "" {
				output = append(output, map[string]any{
					"id":             fmt.Sprintf("ig_%d", i+1),
					"type":           "image_generation_call",
					"status":         "completed",
					"result":         b64,
					"revised_prompt": firstNonEmpty(clean(item["revised_prompt"]), prompt),
				})
			}
		}
		return map[string]any{
			"id":         id,
			"object":     "response",
			"created_at": created,
			"status":     "completed",
			"error":      nil,
			"model":      model,
			"output":     output,
			"usage":      ImageUsage(prompt, len(output)),
		}, nil
	}
	if HasWebSearchTool(body) && !HasUnsupportedTools(body, allowedWebSearchTools("image_generation")) {
		if chat == nil || accounts == nil {
			return nil, fmt.Errorf("search upstream is not configured")
		}
		messages := responseMessages(body["input"], body["instructions"])
		if len(messages) == 0 {
			return nil, fmt.Errorf("input text is required")
		}
		token, err := accounts.GetAvailableAccessTokenFor(context.Background(), nil)
		if err != nil {
			return nil, err
		}
		result, err := RunSearch(context.Background(), chat, token, model, messages)
		if err != nil {
			if account.IsInvalidTokenError(err) {
				accounts.MarkInvalidToken(token)
			}
			return nil, err
		}
		text, annotations := SearchTextWithCitations(result)
		searchItem := webSearchCallItem(SearchPromptFromMessages(messages), NormalizedSearchSources(result))
		messageItem := responseTextOutputItem(text, annotations)
		return map[string]any{
			"id":         id,
			"object":     "response",
			"created_at": created,
			"status":     "completed",
			"error":      nil,
			"model":      model,
			"output":     []map[string]any{searchItem, messageItem},
			"usage": map[string]any{
				"input_tokens":  CountMessageTokens(messages, model),
				"output_tokens": CountTextTokens(text, model),
				"total_tokens":  CountMessageTokens(messages, model) + CountTextTokens(text, model),
			},
		}, nil
	}
	if chat == nil || accounts == nil {
		return nil, fmt.Errorf("chat completions upstream is not configured")
	}
	messages := responseMessages(body["input"], body["instructions"])
	if len(messages) == 0 {
		return nil, fmt.Errorf("input text is required")
	}
	token, err := accounts.GetAvailableAccessTokenFor(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	text, err := CollectText(context.Background(), chat, token, model, messages)
	if err != nil {
		if account.IsInvalidTokenError(err) {
			accounts.MarkInvalidToken(token)
		}
		return nil, err
	}
	output := []map[string]any{responseTextOutputItem(text, nil)}
	return map[string]any{
		"id":         id,
		"object":     "response",
		"created_at": created,
		"status":     "completed",
		"error":      nil,
		"model":      model,
		"output":     output,
	}, nil
}

func responseTextOutputItem(text string, annotations []map[string]any) map[string]any {
	content := map[string]any{"type": "output_text", "text": text, "annotations": annotations}
	if annotations == nil {
		content["annotations"] = []any{}
	}
	return map[string]any{
		"id":      "msg_" + newHex(32),
		"type":    "message",
		"status":  "completed",
		"role":    "assistant",
		"content": []map[string]any{content},
	}
}

func webSearchCallItem(query string, sources []map[string]string) map[string]any {
	action := map[string]any{"type": "search", "query": query, "queries": []string{query}}
	if len(sources) > 0 {
		items := make([]map[string]any, 0, len(sources))
		for _, source := range sources {
			if source["url"] != "" {
				items = append(items, map[string]any{"type": "url", "url": source["url"]})
			}
		}
		action["sources"] = items
	}
	return map[string]any{
		"id":     "ws_" + newHex(32),
		"type":   "web_search_call",
		"status": "completed",
		"action": action,
	}
}

func AnthropicMessage(body map[string]any, chat ConversationStreamer, accounts ImageAccountPool) (map[string]any, error) {
	if chat == nil || accounts == nil {
		return nil, fmt.Errorf("messages upstream is not configured")
	}
	model := firstNonEmpty(clean(body["model"]), "auto")
	messages := NormalizeMessages(asMapSlice(body["messages"]))
	if system := MessageText(body["system"]); strings.TrimSpace(system) != "" {
		messages = append([]map[string]any{{"role": "system", "content": system}}, messages...)
	}
	if len(messages) == 0 {
		return nil, fmt.Errorf("messages is required")
	}
	token, err := accounts.GetAvailableAccessTokenFor(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	text, err := CollectText(context.Background(), chat, token, model, messages)
	if err != nil {
		if account.IsInvalidTokenError(err) {
			accounts.MarkInvalidToken(token)
		}
		return nil, err
	}
	return map[string]any{
		"id":            "msg_" + newHex(32),
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"content":       []map[string]any{{"type": "text", "text": text}},
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"usage": map[string]any{
			"input_tokens":  CountMessageTokens(messages, model),
			"output_tokens": CountTextTokens(text, model),
		},
	}, nil
}

func ImageUsage(prompt string, count int) map[string]any {
	input := CountTextTokens(prompt, "gpt-image-1")
	output := 1056 * count
	total := input + output
	return map[string]any{
		"input_tokens":      input,
		"output_tokens":     output,
		"prompt_tokens":     input,
		"completion_tokens": output,
		"total_tokens":      total,
		"input_tokens_details": map[string]any{
			"text_tokens":  input,
			"image_tokens": 0,
		},
		"output_tokens_details": map[string]any{
			"text_tokens":  0,
			"image_tokens": output,
		},
	}
}

func responsePrompt(input any, instructions any) string {
	parts := []string{}
	if text := strings.TrimSpace(clean(instructions)); text != "" {
		parts = append(parts, text)
	}
	switch value := input.(type) {
	case string:
		parts = append(parts, value)
	case map[string]any:
		if content := MessageText(value["content"]); content != "" {
			parts = append(parts, content)
		}
	case []any:
		for _, raw := range value {
			if item, ok := raw.(map[string]any); ok {
				if text := MessageText(item["content"]); text != "" {
					parts = append(parts, text)
					continue
				}
				if text := MessageText([]any{item}); text != "" {
					parts = append(parts, text)
				}
			}
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n\n"))
}

func responseMessages(input any, instructions any) []map[string]any {
	messages := []map[string]any{}
	if text := strings.TrimSpace(clean(instructions)); text != "" {
		messages = append(messages, map[string]any{"role": "system", "content": text})
	}
	switch value := input.(type) {
	case string:
		if strings.TrimSpace(value) != "" {
			messages = append(messages, map[string]any{"role": "user", "content": value})
		}
	case map[string]any:
		if message := responseInputMessage(value); message != nil {
			messages = append(messages, message)
		}
	case []any:
		for _, raw := range value {
			if item, ok := raw.(map[string]any); ok {
				if message := responseInputMessage(item); message != nil {
					messages = append(messages, message)
				}
			}
		}
	}
	return NormalizeMessages(messages)
}

func responseInputMessage(item map[string]any) map[string]any {
	if len(item) == 0 {
		return nil
	}
	role := firstNonEmpty(clean(item["role"]), "user")
	if content, ok := NormalizeMessageContent(item["content"]); ok {
		return map[string]any{"role": role, "content": content}
	}
	if text := MessageText([]any{item}); strings.TrimSpace(text) != "" || ContentHasImage([]any{item}) {
		return map[string]any{"role": role, "content": []any{item}}
	}
	return nil
}

func hasImageTool(tools any) bool {
	return len(imageTool(tools)) > 0
}

func imageTool(tools any) map[string]any {
	for _, raw := range anyList(tools) {
		item := asMap(raw)
		if strings.EqualFold(clean(item["type"]), "image_generation") {
			return item
		}
	}
	return map[string]any{}
}

func promptWithImageQuality(prompt, quality string) string {
	quality = strings.TrimSpace(quality)
	if quality == "" || strings.EqualFold(quality, "auto") {
		return prompt
	}
	return strings.TrimSpace(prompt) + "\n\n输出图片质量为 " + quality + "。"
}
