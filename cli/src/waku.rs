use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 500;

pub struct WakuClient {
    base: String,
    http: reqwest::Client,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WakuMessage {
    payload: String,
    #[serde(rename = "contentTopic")]
    content_topic: String,
    #[serde(rename = "version", skip_serializing_if = "Option::is_none")]
    version: Option<u32>,
}

impl WakuClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self { base: base.into(), http: reqwest::Client::new() }
    }

    pub async fn subscribe(&self, topics: &[&str]) -> anyhow::Result<()> {
        self.http
            .post(format!("{}/relay/v1/subscriptions", self.base))
            .json(topics)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn publish(&self, topic: &str, payload: &serde_json::Value) -> anyhow::Result<()> {
        let encoded = B64.encode(serde_json::to_vec(payload)?);
        let msg = WakuMessage {
            payload: encoded,
            content_topic: topic.to_owned(),
            version: Some(0),
        };
        let url = format!("{}/relay/v1/messages/{}", self.base, urlencoded(topic));
        let mut last_err = anyhow::anyhow!("no attempts");
        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
            }
            match self.http.post(&url).json(&msg).send().await {
                Ok(resp) => match resp.error_for_status() {
                    Ok(_) => return Ok(()),
                    Err(e) => last_err = e.into(),
                },
                Err(e) => last_err = e.into(),
            }
        }
        Err(last_err)
    }

    pub async fn messages(&self, topic: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let resp: Vec<WakuMessage> = self.http
            .get(format!("{}/relay/v1/messages/{}", self.base, urlencoded(topic)))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let mut out = Vec::with_capacity(resp.len());
        for m in resp {
            let bytes = B64.decode(&m.payload)?;
            out.push(serde_json::from_slice(&bytes)?);
        }
        Ok(out)
    }
}

fn urlencoded(s: &str) -> String {
    s.replace('/', "%2F")
}
