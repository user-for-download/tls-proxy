use anyhow::{Context, Result};
use parking_lot::RwLock;
use radix_trie::{Trie, TrieCommon};
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
        if domain.is_empty() {
            return false;
        }
        let domain_lower = domain.to_ascii_lowercase();
        let (matched, reason) = self.blacklist.read().matches_with_reason(&domain_lower);
        if matched {
            debug!(
                "Blacklist hit: {} (Reason: {})",
                domain,
                reason.unwrap_or("unknown".parse().unwrap())
            );
        }
        matched
    }

    pub fn is_whitelisted(&self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }
        let domain_lower = domain.to_ascii_lowercase();
        let (matched, _) = self.whitelist.read().matches_with_reason(&domain_lower);
        if matched {
            debug!("Whitelist hit: {}", domain);
        }
        matched
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
                        } else {
                            warn!("Invalid exact domain in {}: {}", name, d);
                        }
                    }
                    ParsedDomain::Suffix(d) => {
                        if is_valid_domain(&d) {
                            let reversed: String = d.chars().rev().collect();
                            suffix_trie.insert(reversed, ());
                            count += 1;
                        } else {
                            warn!("Invalid suffix domain in {}: {}", name, d);
                        }
                    }
                }
            }

            if count > MAX_DOMAINS {
                anyhow::bail!("Too many domains in {}", name);
            }
        }

        let domain_set = DomainSet { exact, suffix_trie };

        info!(
            "Loaded {}: {} active rules from {} lines ({} exact, {} suffix)",
            name,
            count,
            raw_count,
            domain_set.exact.len(),
            domain_set.suffix_trie.len()
        );

        Ok(domain_set)
    }

    fn parse_domain_line(line: &str) -> Option<ParsedDomain> {
        let mut domain = line.trim();

        if domain.is_empty() || domain.starts_with('#') || domain.starts_with("//") {
            return None;
        }

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
    fn matches_with_reason(&self, domain: &str) -> (bool, Option<String>) {
        if self.exact.contains(domain) {
            return (true, Some("Exact Match".to_string()));
        }

        if !self.suffix_trie.is_empty() {
            let reversed: String = domain.chars().rev().collect();

            if let Some(subtrie) = self.suffix_trie.get_ancestor(&reversed) {
                let key = subtrie.key().unwrap();

                // Case 1: Exact match on the suffix (e.g. rule "example.com", input "example.com")
                if key.len() == reversed.len() {
                    return (true, Some("Exact Suffix Match".to_string()));
                }

                // Case 2: Subdomain match.
                // reversed input: "moc.elpmaxe.bus"
                // key found:      "moc.elpmaxe"
                // We need to ensure that the next character in input is a dot.
                if reversed.as_bytes().get(key.len()) == Some(&b'.') {
                    let matched_suffix: String = key.chars().rev().collect();
                    return (true, Some(format!("Suffix Match: *.{}", matched_suffix)));
                }
            }
        }

        (false, None)
    }
}

#[derive(Debug, PartialEq)]
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
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_validation() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("xn--123.com"));
        assert!(is_valid_domain("my-domain.com"));

        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain(".example.com"));
        assert!(!is_valid_domain("example.com."));
        assert!(!is_valid_domain("ex ample.com"));
        assert!(!is_valid_domain("example..com"));
        assert!(!is_valid_domain(&"a".repeat(300))); // Too long
    }

    #[test]
    fn test_parsing_lines() {
        // Basic
        assert_eq!(
            DomainFilter::parse_domain_line("example.com"),
            Some(ParsedDomain::Exact("example.com".into()))
        );
        // Adblock syntax
        assert_eq!(
            DomainFilter::parse_domain_line("||example.com"),
            Some(ParsedDomain::Exact("example.com".into()))
        );
        // Wildcards
        assert_eq!(
            DomainFilter::parse_domain_line("*.example.com"),
            Some(ParsedDomain::Suffix("example.com".into()))
        );
        assert_eq!(
            DomainFilter::parse_domain_line(".example.com"),
            Some(ParsedDomain::Suffix("example.com".into()))
        );
        // URLs
        assert_eq!(
            DomainFilter::parse_domain_line("https://example.com/foo"),
            Some(ParsedDomain::Exact("example.com".into()))
        );
        // Leading www stripping
        assert_eq!(
            DomainFilter::parse_domain_line("www.example.com"),
            Some(ParsedDomain::Exact("example.com".into()))
        );
        // Comments
        assert_eq!(DomainFilter::parse_domain_line("# comment"), None);
    }

    #[test]
    fn test_trie_matching_logic() {
        let mut set = DomainSet::default();
        // Insert "google.com" into suffix trie -> "moc.elgoog"
        let rev: String = "google.com".chars().rev().collect();
        set.suffix_trie.insert(rev, ());

        // 1. Exact match
        assert!(set.matches_with_reason("google.com").0);
        // 2. Subdomain match
        assert!(set.matches_with_reason("mail.google.com").0);
        assert!(set.matches_with_reason("a.b.google.com").0);
        // 3. No match
        assert!(!set.matches_with_reason("google.co.uk").0);
        // 4. Boundary check (Crucial!) - "notgoogle.com" should NOT match "google.com"
        assert!(!set.matches_with_reason("notgoogle.com").0);
    }

    #[test]
    fn test_filter_integration() {
        let filter = DomainFilter::new();
        // Simulate loading directly into structs to avoid file IO in this specific test
        {
            let mut w = filter.blacklist.write();
            w.exact.insert("bad.com".into());
            let rev: String = "evil.com".chars().rev().collect();
            w.suffix_trie.insert(rev, ());
        }

        assert!(filter.is_blacklisted("bad.com"));
        assert!(!filter.is_blacklisted("good.com"));

        // Trie tests via public API
        assert!(filter.is_blacklisted("evil.com"));
        assert!(filter.is_blacklisted("www.evil.com"));
        assert!(!filter.is_blacklisted("not-evil.com")); // Boundary check
    }

    #[test]
    fn test_file_loading() -> Result<()> {
        let mut temp = tempfile::NamedTempFile::new()?;
        writeln!(temp, "example.com")?;
        writeln!(temp, "*.wildcard.com")?;
        writeln!(temp, "invalid..domain")?; // Should be warned and ignored
        writeln!(temp, "# Comment")?;

        let filter = DomainFilter::new();
        filter.load_blacklist(temp.path())?;

        assert!(filter.is_blacklisted("example.com"));
        assert!(filter.is_blacklisted("foo.wildcard.com"));
        assert!(!filter.is_blacklisted("other.com"));

        Ok(())
    }
}
