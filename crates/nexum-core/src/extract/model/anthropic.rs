//! `AnthropicClient` — HTTP impl talking to `/v1/messages` and
//! `/v1/messages/count_tokens`.

use std::env;
use std::future::Future;
use std::sync::Arc;
use std::sync::mpsc as sync_mpsc;
use std::thread;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::types::{ExtractError, ExtractionOutput, ModelClient, RawRecord};
use crate::extract::digest::SessionDigest;
use crate::extract::model::render::render_digest;
use crate::extract::prompts::current_prompt;

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const MAX_TOKENS_OUTPUT: u32 = 8192;

/// Job dispatched onto the runtime's dedicated thread. Each job is a boxed
/// async future that drives one reqwest call to completion and posts the
/// result back through a oneshot-style sync channel.
type RuntimeJob = Box<dyn FnOnce(reqwest::Client) -> BoxFuture + Send>;
type BoxFuture = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

/// Dedicated tokio runtime running on a worker thread. Calls from the
/// synchronous `ModelClient` trait are forwarded through a channel so the
/// runtime never nests inside a caller's runtime (which would panic with
/// "Cannot start a runtime from within a runtime").
struct RuntimeWorker {
    sender: mpsc::UnboundedSender<RuntimeJob>,
}

impl RuntimeWorker {
    fn spawn(http: reqwest::Client) -> Result<Self, ExtractError> {
        let (tx, mut rx) = mpsc::unbounded_channel::<RuntimeJob>();
        let (ready_tx, ready_rx) = sync_mpsc::sync_channel::<Result<(), String>>(1);
        thread::Builder::new()
            .name("nexum-anthropic-rt".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                rt.block_on(async move {
                    while let Some(job) = rx.recv().await {
                        job(http.clone()).await;
                    }
                });
            })
            .map_err(|e| ExtractError::Http {
                status: 0,
                body: format!("spawn runtime thread: {e}"),
            })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self { sender: tx }),
            Ok(Err(msg)) => Err(ExtractError::Http {
                status: 0,
                body: format!("build runtime: {msg}"),
            }),
            Err(e) => Err(ExtractError::Http {
                status: 0,
                body: format!("runtime ready handshake: {e}"),
            }),
        }
    }

    /// Run `f` on the worker runtime and block until it returns.
    fn run_blocking<F, Fut, T>(&self, f: F) -> Result<T, ExtractError>
    where
        F: FnOnce(reqwest::Client) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, ExtractError>> + Send + 'static,
        T: Send + 'static,
    {
        let (resp_tx, resp_rx) = sync_mpsc::sync_channel::<Result<T, ExtractError>>(1);
        let job: RuntimeJob = Box::new(move |client| {
            Box::pin(async move {
                let out = f(client).await;
                let _ = resp_tx.send(out);
            })
        });
        self.sender.send(job).map_err(|_| ExtractError::Http {
            status: 0,
            body: "runtime worker terminated".into(),
        })?;
        resp_rx.recv().map_err(|e| ExtractError::Http {
            status: 0,
            body: format!("runtime worker dropped reply: {e}"),
        })?
    }
}

pub struct AnthropicClient {
    api_key: String,
    base_url: String,
    model: String,
    worker: Arc<RuntimeWorker>,
}

impl std::fmt::Debug for AnthropicClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit `api_key` to avoid leaking credentials into logs.
        f.debug_struct("AnthropicClient")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

impl AnthropicClient {
    /// Build a client from the env var name (e.g. `"ANTHROPIC_API_KEY"`).
    ///
    /// # Errors
    /// Returns `ExtractError::NoApiKey` if the variable is unset or empty.
    /// Returns `ExtractError::Http` (with `status: 0`) if the tokio runtime
    /// or reqwest client fails to build.
    pub fn from_env_with_model(model: &str, env_var: &str) -> Result<Self, ExtractError> {
        let api_key = env::var(env_var)
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ExtractError::NoApiKey {
                env_var: env_var.to_owned(),
            })?;
        let base_url =
            env::var("NEXUM_ANTHROPIC_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_owned());
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| ExtractError::Http {
                status: 0,
                body: e.to_string(),
            })?;
        let worker = Arc::new(RuntimeWorker::spawn(http)?);
        Ok(Self {
            api_key,
            base_url,
            model: model.to_owned(),
            worker,
        })
    }
}

impl ModelClient for AnthropicClient {
    fn provider_name(&self) -> &'static str {
        "anthropic"
    }

    fn extract(&self, digest: &SessionDigest) -> Result<ExtractionOutput, ExtractError> {
        let prompt = current_prompt();
        let body = MessagesRequest {
            model: self.model.clone(),
            max_tokens: MAX_TOKENS_OUTPUT,
            system: prompt.body.to_owned(),
            messages: vec![MessagesUserTurn {
                role: "user".into(),
                content: render_digest(digest),
            }],
        };
        let url = format!("{}/v1/messages", self.base_url);
        let api_key = self.api_key.clone();
        let resp_text = self.worker.run_blocking(move |http| async move {
            let response = http
                .post(&url)
                .header("x-api-key", api_key)
                .header("anthropic-version", ANTHROPIC_VERSION)
                .json(&body)
                .send()
                .await
                .map_err(|e| ExtractError::Http {
                    status: 0,
                    body: e.to_string(),
                })?;
            let status = response.status();
            let text = response.text().await.map_err(|e| ExtractError::Http {
                status: status.as_u16(),
                body: e.to_string(),
            })?;
            if !status.is_success() {
                return Err(ExtractError::Http {
                    status: status.as_u16(),
                    body: text,
                });
            }
            Ok(text)
        })?;
        parse_anthropic_response(&resp_text)
    }

    fn count_input_tokens(&self, digest: &SessionDigest) -> Result<u32, ExtractError> {
        let prompt = current_prompt();
        let body = MessagesRequest {
            model: self.model.clone(),
            max_tokens: 0,
            system: prompt.body.to_owned(),
            messages: vec![MessagesUserTurn {
                role: "user".into(),
                content: render_digest(digest),
            }],
        };
        let url = format!("{}/v1/messages/count_tokens", self.base_url);
        let api_key = self.api_key.clone();
        let resp: CountTokensResponse = self.worker.run_blocking(move |http| async move {
            let response = http
                .post(&url)
                .header("x-api-key", api_key)
                .header("anthropic-version", ANTHROPIC_VERSION)
                .json(&body)
                .send()
                .await
                .map_err(|e| ExtractError::Http {
                    status: 0,
                    body: e.to_string(),
                })?;
            let status = response.status();
            if !status.is_success() {
                let text = response.text().await.unwrap_or_default();
                return Err(ExtractError::Http {
                    status: status.as_u16(),
                    body: text,
                });
            }
            response.json::<CountTokensResponse>().await.map_err(|e| {
                ExtractError::MalformedResponse {
                    reason: e.to_string(),
                }
            })
        })?;
        Ok(resp.input_tokens)
    }
}

fn parse_anthropic_response(body: &str) -> Result<ExtractionOutput, ExtractError> {
    let parsed: MessagesResponse =
        serde_json::from_str(body).map_err(|e| ExtractError::MalformedResponse {
            reason: format!("response envelope: {e}"),
        })?;
    let concat: String = parsed
        .content
        .into_iter()
        .filter(|b| b.kind == "text")
        .map(|b| b.text)
        .collect::<Vec<_>>()
        .join("\n");
    let trimmed = concat.trim();
    if let Some(rest) = trimmed.strip_prefix("NO RECORDS") {
        let reason = rest
            .trim_start_matches([' ', '—', '-', ':'])
            .trim()
            .to_owned();
        return Ok(ExtractionOutput::NoRecords {
            reason: if reason.is_empty() {
                "no extractable substance".into()
            } else {
                reason
            },
        });
    }
    let docs: Vec<serde_yaml::Value> =
        serde_yaml::from_str(trimmed).map_err(|e| ExtractError::MalformedResponse {
            reason: e.to_string(),
        })?;
    let records: Vec<RawRecord> = docs.into_iter().map(|yaml| RawRecord { yaml }).collect();
    Ok(ExtractionOutput::Records(records))
}

#[derive(Serialize)]
struct MessagesRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<MessagesUserTurn>,
}

#[derive(Serialize)]
struct MessagesUserTurn {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<MessagesContentBlock>,
}

#[derive(Deserialize)]
struct MessagesContentBlock {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
struct CountTokensResponse {
    input_tokens: u32,
}

#[cfg(test)]
mod tests {
    use super::parse_anthropic_response;

    #[test]
    fn parse_no_records_with_em_dash() {
        let body = r#"{"content":[{"type":"text","text":"NO RECORDS — scaffold-only"}]}"#;
        let out = parse_anthropic_response(body).expect("parse");
        if let crate::extract::model::ExtractionOutput::NoRecords { reason } = out {
            assert!(reason.contains("scaffold"));
        } else {
            panic!("expected NoRecords");
        }
    }
}
