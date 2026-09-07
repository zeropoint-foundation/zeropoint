//! Prompt builder — constructs clean completion requests from operator context.

use crate::provider::{ChatMessage, CompletionRequest};
use zp_core::{Capability, Message, MessageRole, OperatorIdentity};

/// Builds completion requests from operator context and conversation history.
pub struct PromptBuilder;

impl PromptBuilder {
    /// Build a completion request from operator context and conversation history.
    ///
    /// This creates a clean prompt containing:
    /// - System prompt (from operator identity, including *who the operator is*)
    /// - Tool definitions (from capabilities)
    /// - Conversation history (from messages)
    /// - User's new message
    ///
    /// No governance, modes, or verification details are included.
    ///
    /// # Why the operator name is in the system prompt
    ///
    /// `OperatorIdentity` carries `name`, and until 2026-08-09 this builder
    /// took the whole struct and used only `base_prompt`. The observable
    /// result: a substrate that had unlocked a hardware-held sovereign root,
    /// derived its keys from it, and signed every request of the session with
    /// them, answered "I don't actually know your personal identity."
    ///
    /// The identity was proven three layers down and did not reach the one
    /// surface where the operator could see it. That is a half-state in the
    /// thing ZeroPoint exists to establish, so the name is now stated.
    ///
    /// This is an *assertion of sovereign context*, not a security control.
    /// The prompt is not a trust boundary and must never be treated as one —
    /// authorization lives in the policy gate and the delegation chain. This
    /// only ensures the substrate speaks from the identity it can prove.
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

        CompletionRequest::new(Self::system_prompt(identity), messages, tools)
    }

    /// Compose the system prompt from the operator identity.
    ///
    /// `base_prompt` supplies the substrate's own framing; the operator line
    /// supplies who it is acting for. An empty or whitespace-only name is
    /// omitted rather than rendered as an empty assertion — claiming to serve
    /// "" is worse than claiming nothing.
    fn system_prompt(identity: &OperatorIdentity) -> String {
        let name = identity.name.trim();
        if name.is_empty() {
            return identity.base_prompt.clone();
        }
        format!(
            "{}\n\nYou are operating on behalf of {}, the sovereign operator of \
             this substrate. Their identity is established by the Genesis root \
             this session was unlocked with — you may address them by name.",
            identity.base_prompt, name
        )
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

        assert!(
            request.system_prompt.starts_with(&identity.base_prompt),
            "base_prompt must remain the opening of the system prompt"
        );
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

    /// The defect this fixes: the operator's name was carried into this
    /// builder and dropped, so the substrate could not name the sovereign it
    /// had just unlocked.
    #[test]
    fn operator_name_reaches_the_system_prompt() {
        let identity = OperatorIdentity {
            name: "kenrom".to_string(),
            ..Default::default()
        };

        let request = PromptBuilder::build(&identity, &[], &[], "who am I?");

        assert!(
            request.system_prompt.contains("kenrom"),
            "the operator's name must appear in the system prompt — the substrate \
             proves this identity cryptographically and must not then disclaim it"
        );
        assert!(request.system_prompt.starts_with(&identity.base_prompt));
    }

    /// An empty name must be omitted, not rendered. Asserting service to ""
    /// is worse than asserting nothing.
    #[test]
    fn empty_operator_name_is_omitted() {
        let identity = OperatorIdentity {
            name: "   ".to_string(),
            ..Default::default()
        };

        let request = PromptBuilder::build(&identity, &[], &[], "hello");

        assert_eq!(
            request.system_prompt, identity.base_prompt,
            "a blank name must leave the system prompt untouched"
        );
    }
}
