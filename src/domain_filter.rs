use anyhow::{Context, Result};
use parking_lot::RwLock;
use radix_trie::{Trie, TrieCommon};
use smallvec::SmallVec;
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

/// Statistics about loaded filter rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterStats {
    pub blacklist_exact: usize,
    pub blacklist_suffix: usize,
    pub whitelist_exact: usize,
    pub whitelist_suffix: usize,
}

impl FilterStats {
    /// Total number of rules across all lists.
    #[must_use]
    pub fn total(&self) -> usize {
        self.blacklist_exact + self.blacklist_suffix + self.whitelist_exact + self.whitelist_suffix
    }
}

/// A thread-safe domain filter supporting exact and suffix (wildcard) matching.
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
    /// Creates a new empty domain filter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blacklist: Arc::new(RwLock::new(DomainSet::default())),
            whitelist: Arc::new(RwLock::new(DomainSet::default())),
        }
    }

    /// Loads a blacklist from a file, replacing any existing blacklist.
    pub fn load_blacklist(&self, path: impl AsRef<Path>) -> Result<()> {
        let new_list = Self::load(path.as_ref(), "blacklist")?;
        *self.blacklist.write() = new_list;
        Ok(())
    }

    /// Loads a whitelist from a file, replacing any existing whitelist.
    pub fn load_whitelist(&self, path: impl AsRef<Path>) -> Result<()> {
        let new_list = Self::load(path.as_ref(), "whitelist")?;
        *self.whitelist.write() = new_list;
        Ok(())
    }

    /// Returns statistics about loaded filter rules.
    #[must_use]
    pub fn stats(&self) -> FilterStats {
        let bl = self.blacklist.read();
        let wl = self.whitelist.read();
        FilterStats {
            blacklist_exact: bl.exact.len(),
            blacklist_suffix: bl.suffix_trie.len(),
            whitelist_exact: wl.exact.len(),
            whitelist_suffix: wl.suffix_trie.len(),
        }
    }

    /// Checks if a domain is in the blacklist.
    #[must_use]
    pub fn is_blacklisted(&self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }

        let domain_lower = to_ascii_lowercase_cow(domain);
        let (matched, reason) = self.blacklist.read().matches_with_reason(&domain_lower);

        if matched {
            debug!(
                "Blacklist hit: {} (Reason: {})",
                domain,
                reason.as_deref().unwrap_or("unknown")
            );
        }

        matched
    }

    /// Checks if a domain is in the whitelist.
    #[must_use]
    pub fn is_whitelisted(&self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }

        let domain_lower = to_ascii_lowercase_cow(domain);
        let (matched, reason) = self.whitelist.read().matches_with_reason(&domain_lower);

        if matched {
            debug!(
                "Whitelist hit: {} (Reason: {})",
                domain,
                reason.as_deref().unwrap_or("unknown")
            );
        }

        matched
    }

    fn load(path: &Path, name: &str) -> Result<DomainSet> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata for {} file: {:?}", name, path))?;

        if metadata.len() > MAX_FILE_SIZE {
            anyhow::bail!(
                "{} file too large: {} bytes (max: {} bytes)",
                name,
                metadata.len(),
                MAX_FILE_SIZE
            );
        }

        let file = File::open(path)
            .with_context(|| format!("Failed to open {} file: {:?}", name, path))?;

        let reader = BufReader::with_capacity(BUFFER_SIZE, file);

        let mut exact = HashSet::new();
        let mut suffix_trie = Trie::new();

        let mut raw_count = 0;
        let mut valid_count = 0;
        let mut invalid_count = 0;

        for line in reader.lines() {
            let line = line.with_context(|| format!("Failed to read line from {}", name))?;
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
                anyhow::bail!(
                    "Too many domains in {}: {} (max: {})",
                    name,
                    valid_count,
                    MAX_DOMAINS
                );
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

        // Skip empty lines and comments
        if domain.is_empty() || domain.starts_with('#') || domain.starts_with("//") {
            return None;
        }

        // Handle adblock-style exception syntax
        domain = domain.strip_prefix("@@").unwrap_or(domain);

        // Handle adblock-style domain anchor
        domain = domain.strip_prefix("||").unwrap_or(domain);

        // Strip URL schemes
        for scheme in ["https://", "http://", "wss://", "ws://"] {
            if let Some(rest) = domain.strip_prefix(scheme) {
                domain = rest;
                break;
            }
        }

        // Remove path, port, query, and fragment
        if let Some(idx) = domain.find(&['/', ':', '?', '#'][..]) {
            domain = &domain[..idx];
        }

        // Take only the first whitespace-delimited token
        domain = domain.split_whitespace().next()?;

        // Remove trailing dots
        domain = domain.trim_end_matches('.');

        // Strip www prefix
        domain = domain.strip_prefix("www.").unwrap_or(domain);

        if domain.is_empty() {
            return None;
        }

        let domain_lower = domain.to_ascii_lowercase();

        // Determine if this is a suffix (wildcard) rule
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
    /// Check with reason tracking for debugging.
    fn matches_with_reason(&self, domain: &str) -> (bool, Option<String>) {
        if self.exact.contains(domain) {
            return (true, Some("Exact Match".to_string()));
        }

        if !self.suffix_trie.is_empty() {
            let reversed = reverse_domain(domain);

            if let Some(subtrie) = self.suffix_trie.get_ancestor(&reversed) {
                let key = subtrie.key().unwrap();

                // Case 1: Exact match on the suffix
                if key.len() == reversed.len() {
                    return (true, Some("Exact Suffix Match".to_string()));
                }

                // Case 2: Subdomain match
                if reversed.as_bytes().get(key.len()) == Some(&b'.') {
                    let matched_suffix: String = key.chars().rev().collect();
                    return (true, Some(format!("Suffix Match: *.{}", matched_suffix)));
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

/// Converts a string to lowercase, avoiding allocation if already lowercase.
#[inline]
fn to_ascii_lowercase_cow(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

/// Reverses a domain string efficiently using a stack buffer for small domains.
#[inline]
fn reverse_domain(domain: &str) -> String {
    let mut buf: SmallVec<[u8; 64]> = SmallVec::with_capacity(domain.len());
    buf.extend(domain.bytes().rev());
    // SAFETY: Input domain is validated ASCII
    unsafe { String::from_utf8_unchecked(buf.into_vec()) }
}

/// Validates a domain according to DNS naming rules.
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LENGTH {
        return false;
    }

    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }

    if domain.starts_with('-') || domain.ends_with('-') {
        return false;
    }

    for label in domain.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LENGTH {
            return false;
        }

        if label.starts_with('-') || label.ends_with('-') {
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
        assert!(is_valid_domain("_dmarc.example.com"));
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain(".example.com"));
        assert!(!is_valid_domain("example..com"));
        assert!(!is_valid_domain("-example.com"));
    }

    #[test]
    fn test_parsing_lines() {
        assert_eq!(
            DomainFilter::parse_domain_line("example.com"),
            Some(ParsedDomain::Exact("example.com".into()))
        );
        assert_eq!(
            DomainFilter::parse_domain_line("*.example.com"),
            Some(ParsedDomain::Suffix("example.com".into()))
        );
        assert_eq!(
            DomainFilter::parse_domain_line("||example.com"),
            Some(ParsedDomain::Exact("example.com".into()))
        );
        assert_eq!(DomainFilter::parse_domain_line("# comment"), None);
    }

    #[test]
    fn test_trie_matching() {
        let mut set = DomainSet::default();
        let rev = reverse_domain("google.com");
        set.suffix_trie.insert(rev, ());

        assert!(set.matches_with_reason("google.com").0);
        assert!(set.matches_with_reason("mail.google.com").0);
        assert!(!set.matches_with_reason("notgoogle.com").0);
    }

    #[test]
    fn test_file_loading() -> Result<()> {
        let mut temp = tempfile::NamedTempFile::new()?;
        writeln!(temp, "example.com")?;
        writeln!(temp, "*.wildcard.com")?;
        writeln!(temp, "# Comment")?;

        let filter = DomainFilter::new();
        filter.load_blacklist(temp.path())?;

        assert!(filter.is_blacklisted("example.com"));
        assert!(filter.is_blacklisted("foo.wildcard.com"));
        assert!(!filter.is_blacklisted("other.com"));

        Ok(())
    }

    #[test]
    fn test_reverse_domain() {
        assert_eq!(reverse_domain("example.com"), "moc.elpmaxe");
    }
}
