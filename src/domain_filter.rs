use anyhow::{Context, Result};
use parking_lot::RwLock;
use radix_trie::{Trie, TrieCommon};
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;
const MAX_DOMAINS: usize = 10_000_000;
const BUFFER_SIZE: usize = 256 * 1024;
const MAX_DOMAIN_LENGTH: usize = 253;
const MAX_LABEL_LENGTH: usize = 63;

pub struct DomainFilter {
    blacklist: Arc<RwLock<DomainSet>>,
    whitelist: Arc<RwLock<DomainSet>>,
}

impl Default for DomainFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainFilter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            blacklist: Arc::new(RwLock::new(DomainSet::default())),
            whitelist: Arc::new(RwLock::new(DomainSet::default())),
        }
    }

    pub fn load_blacklist(&self, path: impl AsRef<Path>) -> Result<()> {
        let new_list = Self::load(path.as_ref(), "blacklist")?;
        let _old_list = {
            let mut write_guard = self.blacklist.write();
            std::mem::replace(&mut *write_guard, new_list)
        };
        Ok(())
    }

    pub fn load_whitelist(&self, path: impl AsRef<Path>) -> Result<()> {
        let new_list = Self::load(path.as_ref(), "whitelist")?;
        let _old_list = {
            let mut write_guard = self.whitelist.write();
            std::mem::replace(&mut *write_guard, new_list)
        };
        Ok(())
    }

    #[must_use]
    pub fn is_blacklisted(&self, domain: &str) -> bool {
        self.check_domain(domain, &self.blacklist, "Blacklist")
    }

    #[must_use]
    pub fn is_whitelisted(&self, domain: &str) -> bool {
        self.check_domain(domain, &self.whitelist, "Whitelist")
    }

    #[inline]
    fn check_domain(&self, domain: &str, set: &Arc<RwLock<DomainSet>>, list_name: &str) -> bool {
        if domain.is_empty() || !domain.is_ascii() {
            return false;
        }

        let domain_lower = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(domain.to_ascii_lowercase())
        } else {
            Cow::Borrowed(domain)
        };

        let (matched, reason) = set.read().matches_with_reason(&domain_lower);

        if matched {
            debug!(
                "{} hit: {} (Reason: {})",
                list_name,
                domain,
                reason.as_deref().unwrap_or("unknown")
            );
        }

        matched
    }

    fn load(path: &Path, name: &str) -> Result<DomainSet> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata for {name} file: {path:?}"))?;

        if metadata.len() > MAX_FILE_SIZE {
            anyhow::bail!(
                "{} file too large: {} bytes (max: {} bytes)",
                name,
                metadata.len(),
                MAX_FILE_SIZE
            );
        }

        let file =
            File::open(path).with_context(|| format!("Failed to open {name} file: {path:?}"))?;
        let reader = BufReader::with_capacity(BUFFER_SIZE, file);

        let mut exact = HashSet::new();
        let mut suffix_trie = Trie::new();
        let mut raw_count = 0;
        let mut valid_count = 0;
        let mut invalid_count = 0;

        for line in reader.lines() {
            let line = line.with_context(|| format!("Failed to read line from {name}"))?;
            raw_count += 1;

            if let Some(parsed) = Self::parse_domain_line(&line) {
                match parsed {
                    ParsedDomain::Exact(d) => {
                        if is_valid_domain(&d) {
                            exact.insert(d);
                            valid_count += 1;
                        } else {
                            warn!("Invalid exact domain in {}: {}", name, d);
                            invalid_count += 1;
                        }
                    }
                    ParsedDomain::Suffix(d) => {
                        if is_valid_domain(&d) {
                            let reversed = reverse_domain(&d);
                            suffix_trie.insert(reversed, ());
                            valid_count += 1;
                        } else {
                            warn!("Invalid suffix domain in {}: {}", name, d);
                            invalid_count += 1;
                        }
                    }
                }
            }

            if valid_count > MAX_DOMAINS {
                anyhow::bail!("Too many domains in {name}: {valid_count} (max: {MAX_DOMAINS})");
            }
        }

        let domain_set = DomainSet { exact, suffix_trie };

        info!(
            "Loaded {}: {} valid rules from {} lines ({} exact, {} suffix, {} invalid)",
            name,
            valid_count,
            raw_count,
            domain_set.exact.len(),
            domain_set.suffix_trie.len(),
            invalid_count
        );

        Ok(domain_set)
    }

    fn parse_domain_line(line: &str) -> Option<ParsedDomain> {
        let mut domain = line.trim();

        if domain.is_empty()
            || domain.starts_with('#')
            || domain.starts_with("//")
            || domain.starts_with('!')
        {
            return None;
        }

        domain = domain.strip_prefix("@@").unwrap_or(domain);

        let mut is_suffix = false;
        if let Some(rest) = domain.strip_prefix("||") {
            domain = rest;
            is_suffix = true;
        }

        for scheme in ["https://", "http://", "wss://", "ws://"] {
            if let Some(rest) = domain.strip_prefix(scheme) {
                domain = rest;
                break;
            }
        }

        if let Some(idx) = domain.find(&['/', ':', '?', '#'][..]) {
            domain = &domain[..idx];
        }

        let mut tokens = domain.split_whitespace();
        let first_token = tokens.next()?;
        domain = if first_token == "0.0.0.0" || first_token == "127.0.0.1" || first_token == "::1" {
            tokens.next().unwrap_or(first_token)
        } else {
            first_token
        };

        domain = domain.trim_end_matches(['.', '^'].as_ref());
        domain = domain.strip_prefix("www.").unwrap_or(domain);

        if domain.is_empty() {
            return None;
        }

        let domain_lower = domain.to_ascii_lowercase();

        if is_suffix || domain_lower.starts_with("*.") || domain_lower.starts_with('.') {
            let clean = domain_lower.trim_start_matches(['*', '.'].as_ref());
            Some(ParsedDomain::Suffix(clean.to_string()))
        } else if let Some(d) = domain_lower.strip_prefix('*') {
            Some(ParsedDomain::Suffix(d.to_string()))
        } else {
            Some(ParsedDomain::Exact(domain_lower))
        }
    }
}

#[derive(Clone)]
struct DomainSet {
    exact: HashSet<String>,
    suffix_trie: Trie<String, ()>,
}

impl Default for DomainSet {
    fn default() -> Self {
        Self {
            exact: HashSet::new(),
            suffix_trie: Trie::new(),
        }
    }
}

impl DomainSet {
    fn matches_with_reason(&self, domain: &str) -> (bool, Option<String>) {
        if self.exact.contains(domain) {
            return (true, Some("Exact Match".to_string()));
        }

        if !self.suffix_trie.is_empty() {
            let reversed = reverse_domain(domain);

            if let Some(subtrie) = self.suffix_trie.get_ancestor(&reversed) {
                let key = subtrie.key().unwrap();

                if key.len() == reversed.len() {
                    return (true, Some("Exact Suffix Match".to_string()));
                }

                if reversed.as_bytes().get(key.len()) == Some(&b'.') {
                    let mut matched_suffix = key.as_bytes().to_vec();
                    matched_suffix.reverse();
                    let suffix_str = unsafe { String::from_utf8_unchecked(matched_suffix) };
                    return (true, Some(format!("Suffix Match: *.{suffix_str}")));
                }
            }
        }

        (false, None)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedDomain {
    Exact(String),
    Suffix(String),
}

#[inline]
fn reverse_domain(domain: &str) -> String {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.reverse();
    unsafe { String::from_utf8_unchecked(bytes) }
}

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LENGTH || !domain.is_ascii() {
        return false;
    }
    if domain.starts_with('.')
        || domain.ends_with('.')
        || domain.starts_with('-')
        || domain.ends_with('-')
    {
        return false;
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > MAX_LABEL_LENGTH
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return false;
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return false;
        }
    }
    true
}
