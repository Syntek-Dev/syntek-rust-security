//! Anthropic Claude API Client
//!
//! Rust client for the Anthropic Claude API with streaming support.

use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use futures_util::StreamExt;
use tokio::sync::mpsc;

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";

#[derive(Debug, Clone)]
pub struct AnthropicClient {
    client: Client,
    api_key: String,
    model: String,
}

#[derive(Debug, Serialize)]
pub struct MessageRequest {
    pub model: String,
    pub max_tokens: u32,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct MessageResponse {
    pub id: String,
    pub model: String,
    pub content: Vec<ContentBlock>,
    pub stop_reason: Option<String>,
    pub usage: Usage,
}

#[derive(Debug, Deserialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum StreamEvent {
    #[serde(rename = "message_start")]
    MessageStart { message: MessageStartData },
    #[serde(rename = "content_block_start")]
    ContentBlockStart { index: u32, content_block: ContentBlock },
    #[serde(rename = "content_block_delta")]
    ContentBlockDelta { index: u32, delta: Delta },
    #[serde(rename = "content_block_stop")]
    ContentBlockStop { index: u32 },
    #[serde(rename = "message_delta")]
    MessageDelta { delta: MessageDeltaData, usage: Usage },
    #[serde(rename = "message_stop")]
    MessageStop,
    #[serde(rename = "ping")]
    Ping,
}

#[derive(Debug, Deserialize)]
pub struct MessageStartData {
    pub id: String,
    pub model: String,
}

#[derive(Debug, Deserialize)]
pub struct Delta {
    #[serde(rename = "type")]
    pub delta_type: String,
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MessageDeltaData {
    pub stop_reason: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AnthropicError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API error: {status} - {message}")]
    Api { status: u16, message: String },
    #[error("Stream error: {0}")]
    Stream(String),
}

impl AnthropicClient {
    pub fn new(api_key: &str) -> Self {
        Self {
            client: Client::new(),
            api_key: api_key.to_string(),
            model: "claude-sonnet-4-20250514".to_string(),
        }
    }

    pub fn with_model(mut self, model: &str) -> Self {
        self.model = model.to_string();
        self
    }

    /// Send a message and get a complete response
    pub async fn send_message(
        &self,
        messages: Vec<Message>,
        system: Option<&str>,
        max_tokens: u32,
    ) -> Result<MessageResponse, AnthropicError> {
        let request = MessageRequest {
            model: self.model.clone(),
            max_tokens,
            messages,
            system: system.map(String::from),
            temperature: None,
            stream: Some(false),
        };

        let response = self.client
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            return Err(AnthropicError::Api { status, message });
        }

        Ok(response.json().await?)
    }

    /// Send a message with streaming response
    pub async fn send_message_stream(
        &self,
        messages: Vec<Message>,
        system: Option<&str>,
        max_tokens: u32,
    ) -> Result<mpsc::Receiver<Result<String, AnthropicError>>, AnthropicError> {
        let request = MessageRequest {
            model: self.model.clone(),
            max_tokens,
            messages,
            system: system.map(String::from),
            temperature: None,
            stream: Some(true),
        };

        let response = self.client
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            return Err(AnthropicError::Api { status, message });
        }

        let (tx, rx) = mpsc::channel(100);

        tokio::spawn(async move {
            let mut stream = response.bytes_stream();
            let mut buffer = String::new();

            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(bytes) => {
                        buffer.push_str(&String::from_utf8_lossy(&bytes));

                        // Process complete SSE events
                        while let Some(pos) = buffer.find("\n\n") {
                            let event = buffer[..pos].to_string();
                            buffer = buffer[pos + 2..].to_string();

                            if let Some(data) = event.strip_prefix("data: ") {
                                if let Ok(evt) = serde_json::from_str::<StreamEvent>(data) {
                                    if let StreamEvent::ContentBlockDelta { delta, .. } = evt {
                                        if let Some(text) = delta.text {
                                            let _ = tx.send(Ok(text)).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(AnthropicError::Stream(e.to_string()))).await;
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Simple chat helper
    pub async fn chat(&self, user_message: &str) -> Result<String, AnthropicError> {
        let messages = vec![Message {
            role: "user".to_string(),
            content: user_message.to_string(),
        }];

        let response = self.send_message(messages, None, 1024).await?;

        Ok(response.content
            .into_iter()
            .filter_map(|c| c.text)
            .collect::<Vec<_>>()
            .join(""))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .expect("ANTHROPIC_API_KEY environment variable required");

    let client = AnthropicClient::new(&api_key);

    // Simple chat
    println!("=== Simple Chat ===");
    let response = client.chat("What is 2 + 2?").await?;
    println!("Response: {}", response);

    // With system prompt
    println!("\n=== With System Prompt ===");
    let messages = vec![Message {
        role: "user".to_string(),
        content: "Write a haiku about Rust programming.".to_string(),
    }];

    let response = client.send_message(
        messages,
        Some("You are a poet who writes about technology."),
        256,
    ).await?;

    for content in response.content {
        if let Some(text) = content.text {
            println!("{}", text);
        }
    }
    println!("\nTokens used: {} in, {} out",
        response.usage.input_tokens,
        response.usage.output_tokens);

    // Streaming
    println!("\n=== Streaming Response ===");
    let messages = vec![Message {
        role: "user".to_string(),
        content: "Count from 1 to 5 slowly.".to_string(),
    }];

    let mut rx = client.send_message_stream(messages, None, 256).await?;

    while let Some(result) = rx.recv().await {
        match result {
            Ok(text) => print!("{}", text),
            Err(e) => eprintln!("Error: {}", e),
        }
    }
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = Message {
            role: "user".to_string(),
            content: "Hello".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("user"));
        assert!(json.contains("Hello"));
    }

    #[test]
    fn test_request_serialization() {
        let request = MessageRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            max_tokens: 1024,
            messages: vec![],
            system: None,
            temperature: None,
            stream: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("system")); // None fields should be skipped
    }
}
