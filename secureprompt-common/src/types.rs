use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroize;

macro_rules! uuid_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<Uuid> for $name {
            fn from(id: Uuid) -> Self {
                Self(id)
            }
        }
    };
}

uuid_newtype!(WorkspaceId);
uuid_newtype!(RequestId);
uuid_newtype!(UserId);
uuid_newtype!(ProviderId);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub reasoning_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
    pub cache_write_tokens: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct TokenVault {
    entries: HashMap<String, SecretValue>,
}

#[derive(Debug, Clone, Default)]
struct SecretValue(String);

impl SecretValue {
    fn new(value: String) -> Self {
        Self(value)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl TokenVault {
    pub fn insert(&mut self, placeholder: String, original: String) {
        self.entries.insert(placeholder, SecretValue::new(original));
    }

    #[must_use]
    pub fn resolve(&self, placeholder: &str) -> Option<&str> {
        self.entries.get(placeholder).map(SecretValue::as_str)
    }

    #[must_use]
    pub fn restore(&self, content: &str) -> String {
        let mut restored = content.to_owned();
        for (placeholder, original) in &self.entries {
            restored = restored.replace(placeholder, original.as_str());
        }
        restored
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub class: String,
    pub confidence: f32,
    pub span: Option<(usize, usize)>,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvent {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub action: String,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyResult {
    pub final_action: String,
    pub events: Vec<PolicyEvent>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderResponse {
    pub content: String,
    pub model: String,
    pub finish_reason: Option<String>,
    pub embedding: Option<Vec<f32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}
