//! Interactive consent: prompt-on-access for `ask`-mode capabilities,
//! with a per-session decision cache and fail-safe (no channel = deny).

use act_policy::consent::{ConsentAsk, ConsentPrompter};

/// Prompts on the controlling terminal. Reads a line from stdin; `y`/`yes`
/// (case-insensitive) allows, anything else (incl. EOF) denies.
pub struct TtyPrompter;

#[async_trait::async_trait]
impl ConsentPrompter for TtyPrompter {
    async fn decide(&self, ask: &ConsentAsk) -> bool {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut stderr = tokio::io::stderr();
        let prompt = format!(
            "\nACT consent: {} — {} ({})\nAllow? [y/N] ",
            ask.cap_id, ask.summary, ask.key
        );
        if stderr.write_all(prompt.as_bytes()).await.is_err() {
            return false;
        }
        let _ = stderr.flush().await;
        let mut line = String::new();
        let mut reader = BufReader::new(tokio::io::stdin());
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => false,
            Ok(_) => matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        }
    }
}
