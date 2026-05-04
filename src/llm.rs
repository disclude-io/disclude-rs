use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::finding::{Finding, ScanResult, Severity, SignalKind};
use crate::language::Language;

const BATCH_PAYLOAD_LIMIT: usize = 6 * 1024;

pub type FindingKey = (PathBuf, usize, usize, SignalKind);
pub type LLMReview = HashMap<FindingKey, LLMVerdict>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Dismissed = 0,
    LikelyBenign = 1,
    Inconclusive = 2,
    Suspicious = 3,
    Confirmed = 4,
}

impl Verdict {
    pub fn score(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMVerdict {
    pub verdict: Verdict,
    pub score: u8,
    pub confidence: f32,
    pub summary: String,
    pub reasoning: String,
}

pub enum LLMProvider {
    Anthropic,
    OpenAI,
    Ollama,
}

pub struct LLMConfig {
    pub provider: LLMProvider,
    pub model: String,
    pub api_key: String,
    pub base_url: String,
}

impl LLMConfig {
    pub fn provider_name(&self) -> &'static str {
        match self.provider {
            LLMProvider::Anthropic => "Anthropic",
            LLMProvider::OpenAI => "OpenAI",
            LLMProvider::Ollama => "Ollama",
        }
    }
}

pub fn finding_key(f: &Finding) -> FindingKey {
    (f.path.clone(), f.line, f.col, f.kind)
}

pub fn finding_id(root: &Path, f: &Finding) -> String {
    let rel = f.path.strip_prefix(root).unwrap_or(&f.path);
    format!("{}:{}:{}", rel.display(), f.line, f.col)
}

pub fn detect_provider(
    llm_provider: Option<&str>,
    llm_model: Option<&str>,
    llm_base_url: Option<&str>,
) -> anyhow::Result<LLMConfig> {
    let (pname, default_model, default_url, key_env) = match llm_provider {
        Some("anthropic") => (
            "anthropic",
            "claude-sonnet-4-6",
            "https://api.anthropic.com",
            "ANTHROPIC_API_KEY",
        ),
        Some("openai") => (
            "openai",
            "gpt-4o-mini",
            "https://api.openai.com",
            "OPENAI_API_KEY",
        ),
        Some("ollama") => (
            "ollama",
            "llama3.2",
            "https://api.ollama.ai",
            "OLLAMA_API_KEY",
        ),
        Some(other) => {
            anyhow::bail!(
                "unknown --llm-provider '{}'; expected: anthropic, openai, ollama",
                other
            );
        }
        None => {
            if std::env::var("ANTHROPIC_API_KEY").is_ok() {
                (
                    "anthropic",
                    "claude-sonnet-4-6",
                    "https://api.anthropic.com",
                    "ANTHROPIC_API_KEY",
                )
            } else if std::env::var("OPENAI_API_KEY").is_ok() {
                (
                    "openai",
                    "gpt-4o-mini",
                    "https://api.openai.com",
                    "OPENAI_API_KEY",
                )
            } else if std::env::var("OLLAMA_API_KEY").is_ok() {
                (
                    "ollama",
                    "llama3.2",
                    "https://api.ollama.ai",
                    "OLLAMA_API_KEY",
                )
            } else {
                anyhow::bail!(
                    "disclude --llm requires an API key in the environment.\n\
                     Set one of:\n  ANTHROPIC_API_KEY  (uses Anthropic)\n  \
                     OPENAI_API_KEY    (uses OpenAI)\n  \
                     OLLAMA_API_KEY    (uses Ollama cloud)\n\
                     or pass --llm-provider to specify a provider."
                );
            }
        }
    };

    let api_key = std::env::var(key_env).map_err(|_| {
        anyhow::anyhow!(
            "disclude --llm: provider '{}' selected but {} is not set",
            pname,
            key_env
        )
    })?;

    let provider = match pname {
        "anthropic" => LLMProvider::Anthropic,
        "openai" => LLMProvider::OpenAI,
        _ => LLMProvider::Ollama,
    };

    Ok(LLMConfig {
        provider,
        model: llm_model.unwrap_or(default_model).to_string(),
        api_key,
        base_url: llm_base_url.unwrap_or(default_url).to_string(),
    })
}

pub fn review_scan(result: &ScanResult, config: &LLMConfig) -> anyhow::Result<LLMReview> {
    let batches = build_batches(result);
    if batches.is_empty() {
        return Ok(HashMap::new());
    }

    let system = "You are a security expert reviewing static analysis findings for supply-chain \
                  attacks. Determine whether each finding is a genuine security concern or a \
                  false positive. Be precise and consider context.";

    let mut review: LLMReview = HashMap::new();
    for batch in &batches {
        let id_map: HashMap<String, FindingKey> = batch
            .iter()
            .map(|(key, f, _lang)| (finding_id(&result.root, f), key.clone()))
            .collect();

        let user = build_prompt(&result.root, batch);
        let raw = match &config.provider {
            LLMProvider::Anthropic => call_anthropic(system, &user, config)?,
            LLMProvider::OpenAI | LLMProvider::Ollama => {
                call_openai_compat(system, &user, config)?
            }
        };

        for (key, verdict) in parse_response(&raw, &id_map) {
            review.insert(key, verdict);
        }
    }
    Ok(review)
}

pub fn build_batches(result: &ScanResult) -> Vec<Vec<(FindingKey, Finding, Language)>> {
    let mut batches: Vec<Vec<(FindingKey, Finding, Language)>> = Vec::new();
    let mut current: Vec<(FindingKey, Finding, Language)> = Vec::new();
    let mut current_size: usize = 0;

    for fa in &result.files {
        for f in &fa.findings {
            if f.severity < Severity::Warn {
                continue;
            }
            let sz = f.path.to_string_lossy().len()
                + f.message.len()
                + f.snippet.len()
                + 128;
            if !current.is_empty() && current_size + sz > BATCH_PAYLOAD_LIMIT {
                batches.push(std::mem::take(&mut current));
                current_size = 0;
            }
            current.push((finding_key(f), f.clone(), fa.language));
            current_size += sz;
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

pub fn build_prompt(root: &Path, batch: &[(FindingKey, Finding, Language)]) -> String {
    let n = batch.len();
    let mut out = format!(
        "Analyze the following {n} static-analysis findings from a source code security scan.\n\
         For each finding, determine whether it represents a genuine supply-chain security\n\
         concern or a false positive.\n\n"
    );

    for (_key, f, lang) in batch {
        let id = finding_id(root, f);
        let rel = f.path.strip_prefix(root).unwrap_or(&f.path);
        out.push_str(&format!(
            "Finding {id}\n  File: {} ({}), severity: {}\n  Signal: {}\n  Message: {}\n  Snippet:\n    {}\n\n",
            rel.display(),
            lang.as_str(),
            f.severity.as_str(),
            f.kind.as_str(),
            f.message,
            f.snippet
        ));
    }

    out.push_str(concat!(
        "Respond ONLY with valid JSON:\n",
        "{\n  \"verdicts\": [\n    {\n",
        "      \"id\": \"<relative_path:line:col>\",\n",
        "      \"verdict\": \"confirmed|suspicious|inconclusive|likely_benign|dismissed\",\n",
        "      \"score\": 0-4,\n",
        "      \"confidence\": 0.0-1.0,\n",
        "      \"summary\": \"one sentence\",\n",
        "      \"reasoning\": \"explanation\"\n",
        "    }\n  ]\n}",
    ));
    out
}

pub fn call_anthropic(
    system: &str,
    user: &str,
    config: &LLMConfig,
) -> anyhow::Result<String> {
    let url = format!("{}/v1/messages", config.base_url);
    let body = json!({
        "model": config.model,
        "max_tokens": 2048,
        "system": system,
        "messages": [{"role": "user", "content": user}]
    });

    let resp = ureq::post(&url)
        .header("x-api-key", &config.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .send_json(&body)
        .map_err(|e| anyhow::anyhow!("Anthropic API request failed: {}", e))?;

    let text = resp
        .into_body()
        .read_to_string()
        .map_err(|e| anyhow::anyhow!("failed to read Anthropic response: {}", e))?;

    let parsed: Value = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("failed to parse Anthropic response JSON: {}", e))?;
    Ok(parsed["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string())
}

pub fn call_openai_compat(
    system: &str,
    user: &str,
    config: &LLMConfig,
) -> anyhow::Result<String> {
    let url = format!("{}/v1/chat/completions", config.base_url);
    let body = json!({
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ]
    });

    let resp = ureq::post(&url)
        .header("Authorization", &format!("Bearer {}", config.api_key))
        .header("content-type", "application/json")
        .send_json(&body)
        .map_err(|e| anyhow::anyhow!("OpenAI-compatible API request failed: {}", e))?;

    let text = resp
        .into_body()
        .read_to_string()
        .map_err(|e| anyhow::anyhow!("failed to read API response: {}", e))?;

    let parsed: Value = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("failed to parse API response JSON: {}", e))?;
    Ok(parsed["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .to_string())
}

pub fn parse_response(
    raw: &str,
    id_map: &HashMap<String, FindingKey>,
) -> Vec<(FindingKey, LLMVerdict)> {
    let json_str = extract_json(raw);
    let parsed: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let arr = match parsed["verdicts"].as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    for item in arr {
        let id = match item["id"].as_str() {
            Some(s) => s,
            None => continue,
        };
        let key = match id_map.get(id) {
            Some(k) => k.clone(),
            None => continue,
        };
        out.push((key, parse_verdict(item)));
    }
    out
}

fn extract_json(s: &str) -> &str {
    if let Some(start) = s.find('{') {
        if let Some(end) = s.rfind('}') {
            if end >= start {
                return &s[start..=end];
            }
        }
    }
    s
}

fn parse_verdict(item: &Value) -> LLMVerdict {
    let verdict = match item["verdict"].as_str().unwrap_or("inconclusive") {
        "dismissed" => Verdict::Dismissed,
        "likely_benign" => Verdict::LikelyBenign,
        "suspicious" => Verdict::Suspicious,
        "confirmed" => Verdict::Confirmed,
        _ => Verdict::Inconclusive,
    };
    let score = verdict.score();
    let confidence = item["confidence"].as_f64().unwrap_or(0.5) as f32;
    let summary = item["summary"].as_str().unwrap_or("").to_string();
    let reasoning = item["reasoning"].as_str().unwrap_or("").to_string();
    LLMVerdict {
        verdict,
        score,
        confidence,
        summary,
        reasoning,
    }
}
