use anyhow::{Context, Result};
use parking_lot::RwLock;
use radix_trie::{Trie, TrieCommon};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;
const MAX_DOMAINS: usize = 10_000_000;
const BUFFER_SIZE: usize = 256 * 1024;
const MAX_DOMAIN_LENGTH: usize = 253;
const MAX_LABEL_LENGTH: usize = 63;

pub struct DomainFilter {
    blacklist: Arc<RwLock<DomainSet>>,
    whitelist: Arc<RwLock<DomainSet>>,
}

impl DomainFilter {
    pub fn new() -> Self {
        Self {
            blacklist: Arc::new(RwLock::new(DomainSet::default())),
            whitelist: Arc::new(RwLock::new(DomainSet::default())),
        }
    }

    pub fn load_blacklist(&self, path: impl AsRef<Path>) -> Result<()> {
        let new_list = Self::load(path.as_ref(), "blacklist")?;
        *self.blacklist.write() = new_list;
        Ok(())
    }

    pub fn load_whitelist(&self, path: impl AsRef<Path>) -> Result<()> {
        let new_list = Self::load(path.as_ref(), "whitelist")?;
        *self.whitelist.write() = new_list;
        Ok(())
    }

    pub fn is_blacklisted(&self, domain: &str) -> bool {
        // Common optimization: check if empty before acquiring lock or processing
        if domain.is_empty() { return false; }
        let domain_lower = domain.to_ascii_lowercase();
        self.blacklist.read().matches(&domain_lower)
    }

    pub fn is_whitelisted(&self, domain: &str) -> bool {
        if domain.is_empty() { return false; }
        let domain_lower = domain.to_ascii_lowercase();
        self.whitelist.read().matches(&domain_lower)
    }

    fn load(path: &Path, name: &str) -> Result<DomainSet> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata for {} file: {:?}", name, path))?;

        if metadata.len() > MAX_FILE_SIZE {
            anyhow::bail!("{} file too large", name);
        }

        let file = File::open(path)
            .with_context(|| format!("Failed to open {} file: {:?}", name, path))?;

        let reader = BufReader::with_capacity(BUFFER_SIZE, file);

        let mut exact = HashSet::new();
        let mut suffix_trie = Trie::new();

        let mut raw_count = 0;
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            raw_count += 1;

            if let Some(parsed) = Self::parse_domain_line(&line) {
                match parsed {
                    ParsedDomain::Exact(d) => {
                        if is_valid_domain(&d) {
                            exact.insert(d);
                            count += 1;
                        }
                    }
                    ParsedDomain::Suffix(d) => {
                        if is_valid_domain(&d) {
                            // Insert into trie reversed: "example.com" -> "moc.elpmaxe"
                            let reversed: String = d.chars().rev().collect();
                            suffix_trie.insert(reversed, ());
                            count += 1;
                        }
                    }
                }
            }

            if count > MAX_DOMAINS {
                anyhow::bail!("Too many domains in {}", name);
            }
        }

        let domain_set = DomainSet {
            exact,
            suffix_trie,
        };

        tracing::info!(
            "Loaded {}: {} active rules from {} lines",
            name, count, raw_count
        );

        Ok(domain_set)
    }

    fn parse_domain_line(line: &str) -> Option<ParsedDomain> {
        let mut domain = line.trim();

        if domain.is_empty() || domain.starts_with('#') || domain.starts_with("//") {
            return None;
        }

        // Basic adblock syntax cleanup
        domain = domain.strip_prefix("@@").unwrap_or(domain);
        domain = domain.strip_prefix("||").unwrap_or(domain);

        for scheme in ["https://", "http://", "wss://", "ws://"] {
            if let Some(rest) = domain.strip_prefix(scheme) {
                domain = rest;
                break;
            }
        }

        if let Some(idx) = domain.find(&['/', ':', '?', '#'][..]) {
            domain = &domain[..idx];
        }

        domain = domain.split_whitespace().next()?;
        domain = domain.trim_end_matches('.');
        domain = domain.strip_prefix("www.").unwrap_or(domain);

        if domain.is_empty() {
            return None;
        }

        let domain_lower = domain.to_ascii_lowercase();

        // Determine type.
        // *.example.com -> Suffix "example.com"
        // .example.com  -> Suffix "example.com"
        // *example.com  -> Suffix "example.com" (Treated same for perf, enforces dot boundary)

        if let Some(d) = domain_lower.strip_prefix("*.") {
            Some(ParsedDomain::Suffix(d.to_string()))
        } else if let Some(d) = domain_lower.strip_prefix('.') {
            Some(ParsedDomain::Suffix(d.to_string()))
        } else if let Some(d) = domain_lower.strip_prefix('*') {
            Some(ParsedDomain::Suffix(d.to_string()))
        } else {
            Some(ParsedDomain::Exact(domain_lower))
        }
    }
}

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
    fn matches(&self, domain: &str) -> bool {
        if self.exact.contains(domain) {
            return true;
        }

        // Check Suffix Trie
        // We reverse the domain: "mail.google.com" -> "moc.elgoog.liam"
        // Trie contains "moc.elgoog"
        if !self.suffix_trie.is_empty() {
            let reversed: String = domain.chars().rev().collect();

            if let Some(subtrie) = self.suffix_trie.get_ancestor(&reversed) {
                // We found a prefix in the reversed string (which is a suffix in original)
                // e.g. Found "moc.elgoog" inside "moc.elgoog.liam"
                let key = subtrie.key().unwrap();

                // If lengths match, it's an exact match on the suffix rule (e.g. "google.com")
                if key.len() == reversed.len() {
                    return true;
                }

                // If shorter, we must ensure boundary is a dot.
                // reversed: "moc.elgoog.liam" (len 15)
                // key:      "moc.elgoog"      (len 10)
                // Check char at index 10 in reversed.
                if reversed.as_bytes().get(key.len()) == Some(&b'.') {
                    return true;
                }
            }
        }

        false
    }
}

enum ParsedDomain {
    Exact(String),
    Suffix(String),
}

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LENGTH {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    let labels = domain.split('.');
    for label in labels {
        if label.is_empty() || label.len() > MAX_LABEL_LENGTH {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return false;
        }
    }
    true
}