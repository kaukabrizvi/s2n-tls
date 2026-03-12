use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{record::FrozenHandshakeRecord, static_lists::{Cipher, Group, Signature, Version}};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Attribution {
    /// e.g. LLB/frontend
    pub service: String,
    /// e.g. arn:aws:localloadbalancer:us-west-2:111122223333:listener/app/my-balancer/b913be9e027f3ac9/57a83f3316599c34
    pub resource: String,
    /// e.g. arn:aws:acm:us-west-2:111122223333:certificate/cb0c2d78-6bb7-4c93-90c5-680f760ec45c
    pub certificate: Option<String>,
    /// e.g. "1.3.21"
    pub s2n_version: String,
    /// e.g. "20250901"z
    pub security_policy: String,
}

