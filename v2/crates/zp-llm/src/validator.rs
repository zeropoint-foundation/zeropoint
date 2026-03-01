//! Validates completion requests and responses.

use crate::provider::{CompletionRequest, CompletionResponse};
use zp_core::ZpError;

/// Validates completion requests and responses.
pub struct RequestValidator;

impl RequestValidator {
    /// Validate a completion request.
    pub fn validate_request(request: &CompletionRequest) -> Result<(), ZpError> {
        // System prompt must not be empty
        if request.system_prompt.trim().is_empty() {
            return Err(ZpError::Config("System prompt cannot be empty".to_string()));
        }

        // Must have at least one message
        if request.messages.is_empty() {
            return Err(ZpError::Config(
                "Request must have at least one message".to_string(),
            ));
        }

        // Temperature must be in valid range if specified
        if let Some(temp) = request.temperature {
            if !(0.0..=2.0).contains(&temp) {
                return Err(ZpError::Config(
                    "Temperature must be between 0.0 and 2.0".to_string(),
                ));
            }
        }

        // Max tokens should be reasonable (not more than 128k)
        if let Some(max_tokens) = request.max_tokens {
            if max_tokens == 0 || max_tokens > 128_000 {
                return Err(ZpError::Config(
                    "max_tokens must be between 1 and 128,000".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate a completion response.
    pub fn validate_response(response: &CompletionResponse) -> Result<(), ZpError> {
        // Content must not be empty
        if response.content.trim().is_empty() {
            return Err(ZpError::ProviderError {
                provider: response.model.clone(),
                message: "Empty response content".to_string(),
            });
        }

        // Model name must be provided
        if response.model.trim().is_empty() {
            return Err(ZpError::ProviderError {
                provider: "unknown".to_string(),
                message: "Model name not provided in response".to_string(),
            });
        }

        // Prompt tokens should be reasonable
        if response.usage.prompt_tokens > 1_000_000 {
            return Err(ZpError::ProviderError {
                provider: response.model.clone(),
                message: "Unreasonably high prompt token count".to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ChatMessage, Usage};

    #[test]
    fn test_validate_request_valid() {
        let request = CompletionRequest {
            system_prompt: "You are helpful".to_string(),
            messages: vec![ChatMessage::user("Hello".to_string())],
            tools: vec![],
            model: None,
            max_tokens: Some(1000),
            temperature: Some(0.7),
        };

        assert!(RequestValidator::validate_request(&request).is_ok());
    }

    #[test]
    fn test_validate_request_empty_system() {
        let request = CompletionRequest {
            system_prompt: "".to_string(),
            messages: vec![ChatMessage::user("Hello".to_string())],
            tools: vec![],
            model: None,
            max_tokens: None,
            temperature: None,
        };

        assert!(RequestValidator::validate_request(&request).is_err());
    }

    #[test]
    fn test_validate_request_no_messages() {
        let request = CompletionRequest {
            system_prompt: "You are helpful".to_string(),
            messages: vec![],
            tools: vec![],
            model: None,
            max_tokens: None,
            temperature: None,
        };

        assert!(RequestValidator::validate_request(&request).is_err());
    }

    #[test]
    fn test_validate_request_invalid_temperature() {
        let request = CompletionRequest {
            system_prompt: "You are helpful".to_string(),
            messages: vec![ChatMessage::user("Hello".to_string())],
            tools: vec![],
            model: None,
            max_tokens: None,
            temperature: Some(2.5),
        };

        assert!(RequestValidator::validate_request(&request).is_err());
    }

    #[test]
    fn test_validate_response_valid() {
        let response = CompletionResponse {
            content: "This is a valid response".to_string(),
            tool_calls: vec![],
            model: "gpt-4".to_string(),
            usage: Usage {
                prompt_tokens: 10,
                completion_tokens: 20,
            },
        };

        assert!(RequestValidator::validate_response(&response).is_ok());
    }

    #[test]
    fn test_validate_response_empty_content() {
        let response = CompletionResponse {
            content: "".to_string(),
            tool_calls: vec![],
            model: "gpt-4".to_string(),
            usage: Usage {
                prompt_tokens: 10,
                completion_tokens: 0,
            },
        };

        assert!(RequestValidator::validate_response(&response).is_err());
    }
}
