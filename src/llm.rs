use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::finding::{Finding, ScanResult, Severity, SignalKind};
use crate::language::Language;

const BATCH_PAYLOAD_LIMIT: usize = 6 * 1024;

/// `max_tokens` for Anthropic requests. Current models think by default
/// (Claude Haiku 5.5 at `medium` effort), and thinking counts against this
/// limit, so it leaves room for both the thinking and the JSON verdicts.
const ANTHROPIC_MAX_TOKENS: u32 = 16_000;

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

impl LLMProvider {
    pub fn name(&self) -> &'static str {
        match self {
            LLMProvider::Anthropic => "Anthropic",
            LLMProvider::OpenAI => "OpenAI",
            LLMProvider::Ollama => "Ollama",
        }
    }

    fn defaults(&self) -> (&'static str, &'static str, &'static str) {
        match self {
            LLMProvider::Anthropic => (
                "claude-haiku-5-5",
                "https://api.anthropic.com",
                "ANTHROPIC_API_KEY",
            ),
            LLMProvider::OpenAI => ("gpt-4o-mini", "https://api.openai.com", "OPENAI_API_KEY"),
            LLMProvider::Ollama => ("llama3.2", "https://api.ollama.ai", "OLLAMA_API_KEY"),
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "anthropic" => Some(LLMProvider::Anthropic),
            "openai" => Some(LLMProvider::OpenAI),
            "ollama" => Some(LLMProvider::Ollama),
            _ => None,
        }
    }
}

pub struct LLMConfig {
    pub provider: LLMProvider,
    pub model: String,
    pub api_key: String,
    pub base_url: String,
}

impl LLMConfig {
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }
}

pub fn finding_key(f: &Finding) -> FindingKey {
    (f.path.clone(), f.line, f.col, f.kind)
}

pub fn finding_id(root: &Path, f: &Finding) -> String {
    let rel = match f.path.strip_prefix(root) {
        Ok(p) if !p.as_os_str().is_empty() => p,
        _ => &f.path,
    };
    format!("{}:{}:{}", rel.display(), f.line, f.col)
}

/// The id of each finding in a batch, as the prompt shows it and the model
/// answers with: `finding_id`, made unique. Findings of different kinds can
/// share a location (a line both long and high in entropy); the second and
/// later ones get `#2`, `#3`, and so on, or their verdicts would collide.
pub fn batch_ids(root: &Path, batch: &[(FindingKey, Finding, Language)]) -> Vec<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    batch
        .iter()
        .map(|(_key, f, _lang)| {
            let id = finding_id(root, f);
            let n = seen.entry(id.clone()).or_insert(0);
            *n += 1;
            if *n == 1 {
                id
            } else {
                format!("{id}#{n}")
            }
        })
        .collect()
}

pub fn detect_provider(
    llm_provider: Option<&str>,
    llm_model: Option<&str>,
    llm_base_url: Option<&str>,
) -> anyhow::Result<LLMConfig> {
    let provider = match llm_provider {
        Some(s) => LLMProvider::from_str(s).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown --llm-provider '{}'; expected: anthropic, openai, ollama",
                s
            )
        })?,
        None => {
            if std::env::var("ANTHROPIC_API_KEY").is_ok() {
                LLMProvider::Anthropic
            } else if std::env::var("OPENAI_API_KEY").is_ok() {
                LLMProvider::OpenAI
            } else if std::env::var("OLLAMA_API_KEY").is_ok() {
                LLMProvider::Ollama
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

    let (default_model, default_url, key_env) = provider.defaults();
    let api_key = std::env::var(key_env).map_err(|_| {
        anyhow::anyhow!(
            "disclude --llm: provider '{}' selected but {} is not set",
            provider.name(),
            key_env
        )
    })?;

    Ok(LLMConfig {
        provider,
        model: llm_model.unwrap_or(default_model).to_string(),
        api_key,
        base_url: llm_base_url.unwrap_or(default_url).to_string(),
    })
}

/// Instructions shared by every batch. They are sent as the system prompt,
/// marked for prompt caching: identical in every request of a scan (and
/// across scans), they are read from the cache after the first request. Only
/// the findings, in the user message, change from batch to batch.
const SYSTEM_PROMPT: &str = "\
You are a security expert reviewing findings from disclude, a code obfuscation and supply-chain attack scanner. \
disclude runs three analysis passes: (1) raw: byte-level patterns such as unicode anomalies, encoded blobs, and high-entropy strings; \
(2) token: identifier and string-construction patterns such as concatenated sensitive names or macro redefinitions; \
(3) ast: semantic patterns such as dynamic execution, shell calls, and encoded dropper pipelines. \
Raw findings have a higher false-positive rate than AST findings.

Each message lists findings, each headed `Finding <id>` and followed by its file, language, severity, pass, signal, message and snippet. \
For each finding, determine whether it represents genuine obfuscation or malicious intent versus a legitimate coding pattern. \
Consider the pass type, signal, snippet, and file context.

Give exactly one verdict per finding, using its id exactly as written. Respond ONLY with valid JSON:
{\"verdicts\": [{\"id\": \"<id>\", \"verdict\": \"confirmed|suspicious|inconclusive|likely_benign|dismissed\", \
\"confidence\": <0.0-1.0>, \"summary\": \"<one sentence>\", \"reasoning\": \"<explanation>\"}]}";

pub fn review_scan(result: &ScanResult, config: &LLMConfig) -> anyhow::Result<LLMReview> {
    let batches = build_batches(result);
    if batches.is_empty() {
        return Ok(HashMap::new());
    }

    let mut review: LLMReview = HashMap::new();
    for batch in &batches {
        let ids = batch_ids(&result.root, batch);
        let id_map: HashMap<String, FindingKey> = ids
            .iter()
            .zip(batch)
            .map(|(id, (key, _f, _lang))| (id.clone(), key.clone()))
            .collect();

        let user = build_prompt(&result.root, batch);
        let raw = match &config.provider {
            LLMProvider::Anthropic => call_anthropic(SYSTEM_PROMPT, &user, config)?,
            LLMProvider::OpenAI | LLMProvider::Ollama => {
                call_openai_compat(SYSTEM_PROMPT, &user, config)?
            }
        };

        for (key, verdict) in parse_response(&raw, &id_map) {
            review.insert(key, verdict);
        }
    }
    Ok(review)
}

const DEMOTION_CONFIDENCE: f32 = 0.70;

/// Demote findings the LLM assessed as `dismissed` or `likely_benign` with
/// sufficient confidence from WARN/CRITICAL down to INFO. Recomputes the
/// severity counts in `result` so the summary line stays accurate.
pub fn apply_llm_verdicts(result: &mut ScanResult, review: &LLMReview) {
    for fa in &mut result.files {
        for f in &mut fa.findings {
            if f.severity < Severity::Warn {
                continue;
            }
            if let Some(v) = review.get(&finding_key(f)) {
                if matches!(v.verdict, Verdict::Dismissed | Verdict::LikelyBenign)
                    && v.confidence >= DEMOTION_CONFIDENCE
                {
                    f.severity = Severity::Info;
                }
            }
        }
    }

    result.findings_by_severity.clear();
    for fa in &result.files {
        for f in &fa.findings {
            *result.findings_by_severity.entry(f.severity).or_insert(0) += 1;
        }
    }
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
            let sz = f.path.to_string_lossy().len() + f.message.len() + f.snippet.len() + 128;
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

/// The user message for a batch: the findings alone. The instructions and
/// answer format are in `SYSTEM_PROMPT`.
pub fn build_prompt(root: &Path, batch: &[(FindingKey, Finding, Language)]) -> String {
    let n = batch.len();
    let mut out = format!("Review these {n} findings.\n\n");

    for (id, (_key, f, lang)) in batch_ids(root, batch).iter().zip(batch) {
        let rel = f.path.strip_prefix(root).unwrap_or(&f.path);
        let pass = match f.pass {
            crate::finding::PassKind::Raw => "raw",
            crate::finding::PassKind::Token => "token",
            crate::finding::PassKind::Ast => "ast",
        };
        out.push_str(&format!(
            "Finding {id}\n  File: {} ({}), severity: {}, pass: {}\n  Signal: {}\n  Message: {}\n  Snippet:\n    {}\n\n",
            rel.display(),
            lang.as_str(),
            f.severity.as_str(),
            pass,
            f.kind.as_str(),
            f.message,
            f.snippet
        ));
    }
    out
}

/// The JSON schema of a review: Anthropic's structured outputs hold the
/// model to it. Asked for JSON in the prompt alone, Claude Haiku 5.5 now and
/// then answers in Markdown instead (seen reviewing dotenv's README), which
/// leaves no verdicts.
fn verdicts_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "verdicts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "The finding's id, exactly as after `Finding` in the message"
                        },
                        "verdict": {
                            "type": "string",
                            "enum": ["confirmed", "suspicious", "inconclusive", "likely_benign", "dismissed"]
                        },
                        "confidence": {
                            "type": "number",
                            "description": "How sure the verdict is, from 0.0 (a guess) to 1.0 (certain)"
                        },
                        "summary": {
                            "type": "string",
                            "description": "One sentence on what the flagged code is"
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Why the verdict follows from the snippet and its context"
                        }
                    },
                    "required": ["id", "verdict", "confidence", "summary", "reasoning"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["verdicts"],
        "additionalProperties": false
    })
}

pub fn call_anthropic(system: &str, user: &str, config: &LLMConfig) -> anyhow::Result<String> {
    let url = format!("{}/v1/messages", config.base_url);
    let mut body = json!({
        "model": config.model,
        "max_tokens": ANTHROPIC_MAX_TOKENS,
        "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": user}],
        "output_config": {"format": {"type": "json_schema", "schema": verdicts_schema()}}
    });

    let send = |body: &Value| {
        ureq::post(&url)
            .header("x-api-key", &config.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .send_json(body)
    };
    // A model without structured outputs rejects the request (400): ask
    // again without it, relying on the prompt as before.
    let resp = match send(&body) {
        Err(ureq::Error::StatusCode(400)) => {
            body.as_object_mut().map(|b| b.remove("output_config"));
            send(&body)
        }
        other => other,
    }
    .map_err(|e| anyhow::anyhow!("Anthropic API request failed: {}", e))?;

    let text = resp
        .into_body()
        .read_to_string()
        .map_err(|e| anyhow::anyhow!("failed to read Anthropic response: {}", e))?;

    let parsed: Value = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("failed to parse Anthropic response JSON: {}", e))?;
    anthropic_response_text(&parsed)
}

/// The answer in a Messages API response: every `text` block, joined in
/// order. Models that think put `thinking` blocks before the answer, so the
/// first content block is not necessarily text. A response with no text, or
/// one cut off at `max_tokens`, is an error rather than an empty answer.
pub fn anthropic_response_text(parsed: &Value) -> anyhow::Result<String> {
    let stop_reason = parsed["stop_reason"].as_str().unwrap_or("unknown");
    if stop_reason == "max_tokens" {
        anyhow::bail!("Anthropic response was cut off at max_tokens ({ANTHROPIC_MAX_TOKENS})");
    }
    let text: String = parsed["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|block| block["type"] == "text")
        .filter_map(|block| block["text"].as_str())
        .collect();
    if text.trim().is_empty() {
        anyhow::bail!("Anthropic response contained no text (stop_reason: {stop_reason})");
    }
    Ok(text)
}

pub fn call_openai_compat(system: &str, user: &str, config: &LLMConfig) -> anyhow::Result<String> {
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
        Err(e) => {
            // Show the start of what came back: a refusal or prose with no
            // JSON object otherwise leaves nothing to go on.
            let start: String = raw.trim().chars().take(300).collect();
            eprintln!("disclude: llm response parse error: {e}; response began: {start:?}");
            return Vec::new();
        }
    };

    let arr = match parsed["verdicts"].as_array() {
        Some(a) => a,
        None => {
            eprintln!("disclude: llm response missing 'verdicts' array");
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    let (mut unknown, mut degenerate) = (0, 0);
    for item in arr {
        let Some(key) = item["id"].as_str().and_then(|id| id_map.get(id.trim())) else {
            unknown += 1;
            continue;
        };
        if is_degenerate(item) {
            degenerate += 1;
            continue;
        }
        out.push((key.clone(), parse_verdict(item)));
    }
    if unknown + degenerate > 0 {
        eprintln!(
            "disclude: llm response: {unknown} verdict(s) with unknown ids and {degenerate} without substance skipped"
        );
    }
    out
}

/// A verdict that fills the schema without answering: confidence missing,
/// zero or out of range, or no summary (Claude Haiku 5.5 now and then
/// returns `0.0` and an empty or "placeholder" summary). Taking it would
/// record a non-answer, or demote nothing while looking reviewed; skipping
/// it leaves the finding without a verdict, which callers can ask about
/// again.
fn is_degenerate(item: &Value) -> bool {
    let confidence = item["confidence"].as_f64().unwrap_or(f64::NAN);
    let summary = item["summary"].as_str().unwrap_or("").trim();
    !(confidence > 0.0 && confidence <= 1.0)
        || summary.is_empty()
        || summary.eq_ignore_ascii_case("placeholder")
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

#[cfg(test)]
mod tests {

    #[test]
    fn verdicts_schema_is_strict() {
        // Structured outputs need every property listed in `required` and
        // `additionalProperties: false`, at each object level.
        let schema = verdicts_schema();
        let item = &schema["properties"]["verdicts"]["items"];
        for obj in [&schema, item] {
            let props: Vec<&String> = obj["properties"].as_object().unwrap().keys().collect();
            let required: Vec<&str> = obj["required"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            assert_eq!(props.len(), required.len());
            assert!(props.iter().all(|p| required.contains(&p.as_str())));
            assert_eq!(obj["additionalProperties"], false);
        }
        // The verdict values are the ones parse_verdict reads.
        let values = item["properties"]["verdict"]["enum"].as_array().unwrap();
        for v in values {
            let parsed = parse_verdict(&json!({"verdict": v}));
            assert_eq!(serde_json::to_value(parsed.verdict).unwrap(), *v, "{v}");
        }
    }

    use super::*;

    #[test]
    fn text_after_thinking_blocks_is_the_answer() {
        let resp = json!({
            "stop_reason": "end_turn",
            "content": [
                {"type": "thinking", "thinking": "", "signature": "sig"},
                {"type": "text", "text": "{\"verdicts\": "},
                {"type": "text", "text": "[]}"}
            ]
        });
        assert_eq!(
            anthropic_response_text(&resp).unwrap(),
            "{\"verdicts\": []}"
        );
    }

    #[test]
    fn plain_text_responses_still_work() {
        let resp = json!({
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "{\"verdicts\": []}"}]
        });
        assert_eq!(
            anthropic_response_text(&resp).unwrap(),
            "{\"verdicts\": []}"
        );
    }

    #[test]
    fn no_text_or_truncation_is_an_error() {
        let thinking_only = json!({
            "stop_reason": "end_turn",
            "content": [{"type": "thinking", "thinking": "", "signature": "sig"}]
        });
        assert!(anthropic_response_text(&thinking_only).is_err());
        let refusal = json!({"stop_reason": "refusal", "content": []});
        let err = anthropic_response_text(&refusal).unwrap_err().to_string();
        assert!(err.contains("refusal"), "{err}");
        let cut = json!({
            "stop_reason": "max_tokens",
            "content": [{"type": "text", "text": "{\"verdicts\": [{"}]
        });
        assert!(anthropic_response_text(&cut).is_err());
    }

    fn finding(line: usize, kind: SignalKind) -> (FindingKey, Finding, Language) {
        let f = Finding {
            path: PathBuf::from("/repo/src/a.py"),
            byte_offset: 0,
            line,
            col: 1,
            pass: crate::finding::PassKind::Raw,
            kind,
            severity: Severity::Warn,
            confidence: 0.8,
            message: "m".into(),
            snippet: "s".into(),
            diff_introduced: false,
        };
        (finding_key(&f), f, Language::Python)
    }

    #[test]
    fn findings_at_one_location_get_distinct_ids() {
        let batch = [
            finding(3, SignalKind::LongLine),
            finding(3, SignalKind::EncodingHex),
            finding(4, SignalKind::LongLine),
            finding(3, SignalKind::UnicodeBidi),
        ];
        let root = Path::new("/repo");
        assert_eq!(
            batch_ids(root, &batch),
            [
                "src/a.py:3:1",
                "src/a.py:3:1#2",
                "src/a.py:4:1",
                "src/a.py:3:1#3"
            ]
        );
        // The prompt shows the same ids.
        let prompt = build_prompt(root, &batch);
        let shown: Vec<&str> = prompt
            .lines()
            .filter_map(|l| l.strip_prefix("Finding "))
            .collect();
        assert_eq!(shown, batch_ids(root, &batch));
        // The instructions are in the system prompt, not repeated per batch.
        assert!(!prompt.contains("Respond ONLY"));
        assert!(SYSTEM_PROMPT.contains("Respond ONLY with valid JSON"));
        assert!(!SYSTEM_PROMPT.contains("score"), "the schema has no score");
    }

    #[test]
    fn each_colliding_finding_gets_its_own_verdict() {
        let batch = [
            finding(3, SignalKind::LongLine),
            finding(3, SignalKind::EncodingHex),
        ];
        let ids = batch_ids(Path::new("/repo"), &batch);
        let id_map: HashMap<String, FindingKey> = ids
            .iter()
            .zip(&batch)
            .map(|(id, (key, _, _))| (id.clone(), key.clone()))
            .collect();
        let raw = json!({"verdicts": [
            {"id": "src/a.py:3:1", "verdict": "dismissed", "confidence": 0.9,
             "summary": "a long line", "reasoning": "r"},
            {"id": "src/a.py:3:1#2", "verdict": "suspicious", "confidence": 0.8,
             "summary": "hex", "reasoning": "r"}
        ]})
        .to_string();
        let got: HashMap<FindingKey, Verdict> = parse_response(&raw, &id_map)
            .into_iter()
            .map(|(k, v)| (k, v.verdict))
            .collect();
        assert_eq!(got[&batch[0].0], Verdict::Dismissed);
        assert_eq!(got[&batch[1].0], Verdict::Suspicious);
    }

    #[test]
    fn verdicts_without_substance_are_skipped() {
        let (key, _, _) = finding(3, SignalKind::LongLine);
        let id_map = HashMap::from([("src/a.py:3:1".to_string(), key)]);
        let one = |v: Value| parse_response(&json!({ "verdicts": [v] }).to_string(), &id_map);
        let good = json!({"id": "src/a.py:3:1", "verdict": "likely_benign", "confidence": 0.8,
                          "summary": "a minified bundle", "reasoning": "r"});
        assert_eq!(one(good.clone()).len(), 1);
        for (field, bad) in [
            ("confidence", json!(0.0)),
            ("confidence", json!(1.5)),
            ("confidence", Value::Null),
            ("summary", json!("")),
            ("summary", json!(" Placeholder ")),
        ] {
            let mut v = good.clone();
            v[field] = bad.clone();
            assert!(one(v).is_empty(), "{field}: {bad}");
        }
        // Unknown ids are skipped too; a stray space around a known one is not.
        let mut v = good.clone();
        v["id"] = json!("src/a.py:3:2");
        assert!(one(v).is_empty());
        let mut v = good;
        v["id"] = json!(" src/a.py:3:1");
        assert_eq!(one(v).len(), 1);
    }

    #[test]
    fn anthropic_defaults_to_haiku_5_5() {
        let (model, url, key) = LLMProvider::Anthropic.defaults();
        assert_eq!(
            (model, url, key),
            (
                "claude-haiku-5-5",
                "https://api.anthropic.com",
                "ANTHROPIC_API_KEY"
            )
        );
    }
}
