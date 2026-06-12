//! Tokenization for blind field indexes ([`crate::schema::FieldIndex`]).
//!
//! Tokens are derived from the *normalized* (lowercased) plaintext and work in
//! chars, not bytes, so multi-byte text n-grams stay aligned. The same rules
//! must apply on the write side and the probe side or nothing matches.

use crate::schema::FieldIndex;
use std::collections::BTreeSet;

pub(crate) fn normalize(s: &str) -> String {
    s.to_lowercase()
}

/// Index-time tokens for one stored value. Deduplicated and sorted, so the
/// persisted token list is deterministic.
pub(crate) fn value_tokens(text: &str, idx: FieldIndex) -> Vec<String> {
    let norm = normalize(text);
    let chars: Vec<char> = norm.chars().collect();
    let mut out = BTreeSet::new();
    match idx {
        FieldIndex::None => {}
        FieldIndex::Exact => {
            out.insert(norm);
        }
        FieldIndex::Prefix(n) => {
            for len in 1..=n.min(chars.len()) {
                out.insert(chars[..len].iter().collect());
            }
        }
        FieldIndex::Ngram(n) => {
            if chars.len() < n {
                // short values get one whole-value token; probes shorter than
                // n cannot use the index anyway, so this only serves
                // whole-value Contains probes after a fallback scan
                if !chars.is_empty() {
                    out.insert(norm);
                }
            } else {
                for w in chars.windows(n) {
                    out.insert(w.iter().collect());
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Probe tokens for a Contains search against an `Ngram(n)` index, or `None`
/// when the probe is too short to use the index (callers fall back to a scan).
pub(crate) fn ngram_probe_tokens(probe: &str, n: usize) -> Option<Vec<String>> {
    let norm = normalize(probe);
    let chars: Vec<char> = norm.chars().collect();
    if chars.len() < n {
        return None;
    }
    let set: BTreeSet<String> = chars.windows(n).map(|w| w.iter().collect()).collect();
    Some(set.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ngram_tokens_are_char_windows() {
        assert_eq!(
            value_tokens("AbCd", FieldIndex::Ngram(3)),
            vec!["abc".to_string(), "bcd".to_string()]
        );
        // multi-byte chars count as one
        assert_eq!(
            value_tokens("김철수", FieldIndex::Ngram(2)),
            vec!["김철", "철수"]
        );
        // shorter than n -> one whole-value token
        assert_eq!(value_tokens("ab", FieldIndex::Ngram(3)), vec!["ab"]);
    }

    #[test]
    fn prefix_tokens_cover_lengths_up_to_n() {
        assert_eq!(
            value_tokens("Carol", FieldIndex::Prefix(3)),
            vec!["c".to_string(), "ca".to_string(), "car".to_string()]
        );
        assert_eq!(value_tokens("ab", FieldIndex::Prefix(5)), vec!["a", "ab"]);
    }

    #[test]
    fn probe_tokens_match_value_tokens() {
        let value = value_tokens("Carol Danvers", FieldIndex::Ngram(3));
        let probe = ngram_probe_tokens("DANVERS", 3).unwrap();
        assert!(probe.iter().all(|t| value.contains(t)));
        assert!(
            ngram_probe_tokens("da", 3).is_none(),
            "short probe -> fallback"
        );
    }
}
