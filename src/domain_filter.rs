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
        let domain_lower = domain.to_ascii_lowercase();
        self.blacklist.read().matches(&domain_lower)
    }

    pub fn is_whitelisted(&self, domain: &str) -> bool {
        let domain_lower = domain.to_ascii_lowercase();
        self.whitelist.read().matches(&domain_lower)
    }

    #[allow(dead_code)]
    pub fn blacklist_stats(&self) -> DomainSetStats {
        self.blacklist.read().stats()
    }

    #[allow(dead_code)]
    pub fn whitelist_stats(&self) -> DomainSetStats {
        self.whitelist.read().stats()
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

        let mut exact = Vec::new();
        let mut suffix_wildcards_trie = Vec::new();
        let mut suffix_wildcards_vec = Vec::new();
        let mut raw_count = 0;
        let mut invalid_count = 0;

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result
                .with_context(|| format!("Failed to read line {} in {}", line_num + 1, name))?;

            if let Some(domain) = Self::parse_domain_line(&line) {
                raw_count += 1;

                if raw_count > MAX_DOMAINS {
                    anyhow::bail!("{} contains too many domains (max: {})", name, MAX_DOMAINS);
                }

                match domain {
                    ParsedDomain::Exact(d) => {
                        if is_valid_domain(&d) {
                            exact.push(d);
                        } else {
                            invalid_count += 1;
                            tracing::debug!("Invalid exact domain on line {}: {}", line_num + 1, d);
                        }
                    }
                    ParsedDomain::SuffixWildcardTrie(d) => {
                        if is_valid_domain(&d) {
                            suffix_wildcards_trie.push(d);
                        } else {
                            invalid_count += 1;
                            tracing::debug!(
                                "Invalid suffix wildcard on line {}: {}",
                                line_num + 1,
                                d
                            );
                        }
                    }
                    ParsedDomain::SuffixWildcardVec(d) => {
                        if is_valid_domain(&d) {
                            suffix_wildcards_vec.push(d);
                        } else {
                            invalid_count += 1;
                            tracing::debug!("Invalid wildcard on line {}: {}", line_num + 1, d);
                        }
                    }
                }
            }
        }

        exact.sort_unstable();
        exact.dedup();
        suffix_wildcards_trie.sort_unstable();
        suffix_wildcards_trie.dedup();
        suffix_wildcards_vec.sort_unstable();
        suffix_wildcards_vec.dedup();

        suffix_wildcards_vec.sort_by_key(|item| std::cmp::Reverse(item.len()));

        let exact_set = exact.into_iter().collect();
        let mut suffix_trie = Trie::new();
        for suffix in suffix_wildcards_trie {
            let reversed: String = suffix.chars().rev().collect();
            suffix_trie.insert(reversed, ());
        }

        let domain_set = DomainSet {
            exact: exact_set,
            suffix_trie,
            suffix_wildcards: suffix_wildcards_vec,
        };

        let stats = domain_set.stats();
        tracing::info!(
            "Loaded {}: {} unique domains ({} exact, {} suffix trie, {} suffix vec) \
         from {} raw entries ({} invalid)",
            name,
            stats.total,
            stats.exact_count,
            stats.suffix_trie_count,
            stats.suffix_wildcards_count,
            raw_count,
            invalid_count,
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
            domain = domain.strip_prefix(scheme).unwrap_or(domain);
        }

        if let Some(idx) = domain.find(&['/', ':', '?', '#'][..]) {
            domain = &domain[..idx];
        }

        domain = domain.split_whitespace().next()?;

        domain = domain.strip_suffix('.').unwrap_or(domain);

        let has_leading_dot = domain.starts_with('.');

        domain = domain.strip_prefix("www.").unwrap_or(domain);

        if domain.is_empty() {
            return None;
        }

        let domain_lower = domain.to_ascii_lowercase();

        if let Some(d) = domain_lower.strip_prefix("*.") {
            Some(ParsedDomain::SuffixWildcardTrie(d.to_string()))
        } else if has_leading_dot {
            let d = domain_lower.strip_prefix('.').unwrap_or(&domain_lower);
            Some(ParsedDomain::SuffixWildcardTrie(d.to_string()))
        } else if let Some(d) = domain_lower.strip_prefix('*') {
            Some(ParsedDomain::SuffixWildcardVec(d.to_string()))
        } else {
            Some(ParsedDomain::Exact(domain_lower))
        }
    }
}

impl Default for DomainFilter {
    fn default() -> Self {
        Self::new()
    }
}

struct DomainSet {
    exact: HashSet<String>,
    suffix_trie: Trie<String, ()>,
    suffix_wildcards: Vec<String>,
}

impl Default for DomainSet {
    fn default() -> Self {
        Self {
            exact: HashSet::new(),
            suffix_trie: Trie::new(),
            suffix_wildcards: Vec::new(),
        }
    }
}

impl DomainSet {
    #[inline]
    fn matches(&self, domain: &str) -> bool {
        if self.exact.contains(domain) {
            return true;
        }

        for pattern in &self.suffix_wildcards {
            if matches_suffix_or_equal(domain, pattern) {
                return true;
            }
        }

        if matches_suffix_wildcard_trie(domain, &self.suffix_trie) {
            return true;
        }

        false
    }

    fn stats(&self) -> DomainSetStats {
        DomainSetStats {
            exact_count: self.exact.len(),
            suffix_trie_count: self.suffix_trie.len(),
            suffix_wildcards_count: self.suffix_wildcards.len(),
            total: self.exact.len() + self.suffix_trie.len() + self.suffix_wildcards.len(),
        }
    }
}

fn matches_suffix_wildcard_trie(domain: &str, trie: &Trie<String, ()>) -> bool {
    if trie.is_empty() {
        return false;
    }

    let reversed: String = domain.chars().rev().collect();

    if let Some(subtrie) = trie.get_ancestor(&reversed) {
        let key = subtrie.key().unwrap();
        let pattern_len = key.len();

        if pattern_len == reversed.len() {
            return true;
        }
        if pattern_len < reversed.len() {
            return reversed.as_bytes()[pattern_len] == b'.';
        }
    }

    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSetStats {
    pub exact_count: usize,
    pub suffix_trie_count: usize,
    pub suffix_wildcards_count: usize,
    pub total: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedDomain {
    Exact(String),
    SuffixWildcardTrie(String),
    SuffixWildcardVec(String),
}

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LENGTH {
        return false;
    }

    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }

    let labels: Vec<&str> = domain.split('.').collect();

    if labels.is_empty() {
        return false;
    }

    for label in labels {
        if label.is_empty() || label.len() > MAX_LABEL_LENGTH {
            return false;
        }

        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

#[inline]
fn matches_suffix_or_equal(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }

    if domain.len() <= suffix.len() {
        return false;
    }

    let expected_dot_pos = domain.len() - suffix.len() - 1;
    domain.as_bytes()[expected_dot_pos] == b'.' && domain.ends_with(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_file(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_is_valid_domain_valid() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("test.example.com"));
        assert!(is_valid_domain("sub.domain.example.com"));
        assert!(is_valid_domain("test-domain.com"));
        assert!(is_valid_domain("123.com"));
        assert!(is_valid_domain("test123.example456.com"));
        assert!(is_valid_domain("a.b"));
    }

    #[test]
    fn test_is_valid_domain_invalid() {
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain(&"a".repeat(254)));
        assert!(!is_valid_domain(".example.com"));
        assert!(!is_valid_domain("example.com."));
        assert!(!is_valid_domain("example..com"));
        assert!(!is_valid_domain("-example.com"));
        assert!(!is_valid_domain("example-.com"));
        assert!(!is_valid_domain("test.-example.com"));
        assert!(!is_valid_domain("example_test.com"));
        assert!(!is_valid_domain("example.com!"));
        assert!(!is_valid_domain("test@example.com"));
        assert!(!is_valid_domain("example com"));
        assert!(!is_valid_domain(&format!("{}.com", "a".repeat(64))));
    }

    #[test]
    fn test_matches_suffix_or_equal() {
        assert!(matches_suffix_or_equal("example.com", "example.com"));
        assert!(matches_suffix_or_equal("test.example.com", "example.com"));
        assert!(matches_suffix_or_equal("a.b.c.example.com", "example.com"));
        assert!(!matches_suffix_or_equal("notexample.com", "example.com"));
        assert!(!matches_suffix_or_equal("exam", "example.com"));
        assert!(!matches_suffix_or_equal("exam.com", "example.com"));
        assert!(!matches_suffix_or_equal("example.com", "test.example.com"));
        assert!(matches_suffix_or_equal("x.y", "y"));
        assert!(!matches_suffix_or_equal("xy", "y"));
    }

    #[test]
    fn test_parse_domain_line_exact() {
        assert_eq!(
            DomainFilter::parse_domain_line("example.com"),
            Some(ParsedDomain::Exact("example.com".to_string()))
        );
        assert_eq!(
            DomainFilter::parse_domain_line("  test.com  "),
            Some(ParsedDomain::Exact("test.com".to_string()))
        );
        assert_eq!(
            DomainFilter::parse_domain_line("TEST.COM"),
            Some(ParsedDomain::Exact("test.com".to_string()))
        );
    }

    #[test]
    fn test_parse_domain_line_wildcards() {
        assert_eq!(
            DomainFilter::parse_domain_line("*.example.com"),
            Some(ParsedDomain::SuffixWildcardTrie("example.com".to_string()))
        );
        assert_eq!(
            DomainFilter::parse_domain_line(".example.com"),
            Some(ParsedDomain::SuffixWildcardTrie("example.com".to_string()))
        );
        assert_eq!(
            DomainFilter::parse_domain_line("*example.com"),
            Some(ParsedDomain::SuffixWildcardVec("example.com".to_string()))
        );
    }

    #[test]
    fn test_domain_set_suffix_wildcard_trie() {
        let mut set = DomainSet::default();
        let reversed: String = "example.com".chars().rev().collect();
        set.suffix_trie.insert(reversed, ());

        assert!(set.matches("example.com"));
        assert!(set.matches("test.example.com"));
        assert!(set.matches("a.b.example.com"));
        assert!(!set.matches("notexample.com"));
        assert!(!set.matches("exampleXcom"));
        assert!(!set.matches("example.org"));
    }

    #[test]
    fn test_domain_filter_blacklist() {
        let file = create_test_file("example.com\ntest.com\n*.evil.com");

        let filter = DomainFilter::new();
        filter.load_blacklist(file.path()).unwrap();

        assert!(filter.is_blacklisted("example.com"));
        assert!(filter.is_blacklisted("test.com"));
        assert!(filter.is_blacklisted("sub.evil.com"));
        assert!(!filter.is_blacklisted("good.com"));
    }

    #[test]
    fn test_domain_filter_case_insensitive() {
        let file = create_test_file("Example.COM");

        let filter = DomainFilter::new();
        filter.load_blacklist(file.path()).unwrap();

        assert!(filter.is_blacklisted("example.com"));
        assert!(filter.is_blacklisted("EXAMPLE.COM"));
        assert!(filter.is_blacklisted("ExAmPlE.CoM"));
    }

    #[test]
    fn test_domain_count_limit() {
        let domains: Vec<String> = (0..11_000_000)
            .map(|i| format!("{}.co", i % 1000))
            .collect();
        let content = domains.join("\n");

        let file = create_test_file(&content);

        let filter = DomainFilter::new();
        let result = filter.load_blacklist(file.path());

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too many"),
            "Expected 'too many', got: {}",
            err_msg
        );
    }

    #[test]
    fn test_leading_dot_wildcard() {
        assert_eq!(
            DomainFilter::parse_domain_line(".example.com"),
            Some(ParsedDomain::SuffixWildcardTrie("example.com".to_string()))
        );

        let file = create_test_file(".example.com");
        let filter = DomainFilter::new();
        filter.load_blacklist(file.path()).unwrap();

        assert!(filter.is_blacklisted("example.com"));
        assert!(filter.is_blacklisted("test.example.com"));
        assert!(!filter.is_blacklisted("notexample.com"));
    }
}