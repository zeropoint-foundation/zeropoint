//! Prompt builder — constructs clean completion requests from operator context.

use crate::provider::{ChatMessage, CompletionRequest};
use zp_core::{Capability, Message, MessageRole, OperatorIdentity};

/// Builds completion requests from operator context and conversation history.
pub struct PromptBuilder;

impl PromptBuilder {
    /// Build a completion request from operator context and conversation history.
    ///
    /// This creates a clean prompt containing:
    /// - System prompt (from operator identity)
    /// - Tool definitions (from capabilities)
    /// - Conversation history (from messages)
    /// - User's new message
    ///
    /// No governance, modes, or verification details are included.
    pub fn build(
        identity: &OperatorIdentity,
        capabilities: &[Capability],
        history: &[Message],
        user_message: &str,
    ) -> CompletionRequest {
        // Collect all tool definitions from capabilities
        let mut tools = Vec::new();
        for capability in capabilities {
            tools.extend(capability.tools.clone());
        }

        // Build chat history
        let mut messages = Vec::new();

        // Add previous messages (skip system messages — they go in system_prompt)
        for msg in history {
            match msg.role {
                MessageRole::System => {
                    // Skip system messages, they're in the system prompt
                }
                MessageRole::User => {
                    messages.push(ChatMessage::user(msg.content.clone()));
                }
                MessageRole::Operator => {
                    messages.push(ChatMessage::assistant(msg.content.clone()));
                }
                MessageRole::Tool => {
                    messages.push(ChatMessage::tool(msg.content.clone()));
                }
            }
        }

        // Add the current user message
        messages.push(ChatMessage::user(user_message.to_string()));

        CompletionRequest::new(identity.base_prompt.clone(), messages, tools)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ChatRole;

    #[test]
    fn test_build_empty_history() {
        let identity = OperatorIdentity::default();
        let capabilities = vec![];
        let history = vec![];
        let user_message = "Hello";

        let request = PromptBuilder::build(&identity, &capabilities, &history, user_message);

        assert_eq!(request.system_prompt, identity.base_prompt);
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.messages[0].role, ChatRole::User);
        assert_eq!(request.messages[0].content, "Hello");
        assert!(request.tools.is_empty());
    }

    #[test]
    fn test_build_with_history() {
        let identity = OperatorIdentity::default();
        let capabilities = vec![];

        let user_msg = Message {
            id: zp_core::MessageId::new(),
            conversation_id: zp_core::ConversationId::new(),
            role: MessageRole::User,
            content: "Previous question".to_string(),
            tool_calls: vec![],
            timestamp: chrono::Utc::now(),
        };

        let assistant_msg = Message {
            id: zp_core::MessageId::new(),
            conversation_id: zp_core::ConversationId::new(),
            role: MessageRole::Operator,
            content: "Previous answer".to_string(),
            tool_calls: vec![],
            timestamp: chrono::Utc::now(),
        };

        let history = vec![user_msg, assistant_msg];

        let request = PromptBuilder::build(&identity, &capabilities, &history, "Follow-up?");

        assert_eq!(request.messages.len(), 3);
        assert_eq!(request.messages[0].role, ChatRole::User);
        assert_eq!(request.messages[1].role, ChatRole::Assistant);
        assert_eq!(request.messages[2].role, ChatRole::User);
    }
}
