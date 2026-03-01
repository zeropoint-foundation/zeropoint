//! Interactive chat loop for ZeroPoint CLI

use anyhow::Result;
use std::io::{self, BufRead};
use zp_core::{Channel, ConversationId, Request};
use zp_pipeline::Pipeline;

/// Run the interactive chat loop
pub async fn run(pipeline: &Pipeline) -> Result<()> {
    println!("ZeroPoint v2 CLI - Interactive Chat");
    println!("Type /quit to exit, /help for commands");
    println!();

    let stdin = io::stdin();
    let reader = stdin.lock();
    let mut lines = reader.lines();

    // Create a new conversation
    let mut conversation_id = ConversationId::new();
    println!("Started new conversation: {}", conversation_id.0);
    println!();

    loop {
        print!("you> ");
        use std::io::Write;
        io::stdout().flush()?;

        match lines.next() {
            Some(Ok(line)) => {
                let input = line.trim();

                if input.is_empty() {
                    continue;
                }

                // Handle special commands
                match input {
                    "/quit" | "/exit" => {
                        println!("Goodbye!");
                        break;
                    }
                    "/new" => {
                        conversation_id = ConversationId::new();
                        println!("Started new conversation: {}", conversation_id.0);
                        continue;
                    }
                    "/skills" => {
                        println!("Use 'zp skills list' command to view skills");
                        continue;
                    }
                    "/history" => {
                        println!("Conversation ID: {}", conversation_id.0);
                        continue;
                    }
                    "/help" => {
                        print_help();
                        continue;
                    }
                    _ if input.starts_with('/') => {
                        println!(
                            "Unknown command: {}. Type /help for available commands.",
                            input
                        );
                        continue;
                    }
                    _ => {}
                }

                // Send request to pipeline
                let request =
                    Request::new(conversation_id.clone(), input.to_string(), Channel::Cli);

                match pipeline.handle(request).await {
                    Ok(response) => {
                        // Display tool call results if any
                        if !response.tool_calls.is_empty() {
                            for tc in &response.tool_calls {
                                println!("  [tool: {}]", tc.tool_name);
                                if let Some(ref result) = tc.result {
                                    let status = if result.success { "ok" } else { "FAILED" };
                                    println!("  [status: {}]", status);
                                    // Show abbreviated output
                                    let output_str = result.output.to_string();
                                    if output_str.len() > 200 {
                                        println!("  [output: {}...]", &output_str[..200]);
                                    } else {
                                        println!("  [output: {}]", output_str);
                                    }
                                    if let Some(ref receipt) = result.receipt {
                                        let hash_preview = if receipt.content_hash.len() >= 16 {
                                            &receipt.content_hash[..16]
                                        } else {
                                            &receipt.content_hash
                                        };
                                        println!(
                                            "  [receipt: {} grade:{:?}]",
                                            hash_preview, receipt.trust_grade
                                        );
                                    }
                                }
                                println!();
                            }
                        }
                        println!("zp> {}", response.content);
                        println!();
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        println!();
                    }
                }
            }
            Some(Err(e)) => {
                eprintln!("Input error: {}", e);
                break;
            }
            None => {
                // EOF
                println!("\nGoodbye!");
                break;
            }
        }
    }

    Ok(())
}

fn print_help() {
    println!();
    println!("Available commands:");
    println!("  /quit, /exit     - Exit the chat");
    println!("  /new             - Start a new conversation");
    println!("  /skills          - List available skills (use 'zp skills list')");
    println!("  /history         - Show current conversation ID");
    println!("  /help            - Show this help message");
    println!();
    println!("Otherwise, type anything to send a message to ZeroPoint.");
    println!();
}
