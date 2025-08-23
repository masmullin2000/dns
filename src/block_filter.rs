#[cfg(not(any(feature = "bloom", feature = "fatset", feature = "slimset")))]
compile_error!(
    "Filtering features must be enabled. Please enable at least one of: bloom, fatset, slimset."
);

#[cfg(all(feature = "slimset", feature = "fatset"))]
compile_error!(
    "slimset and fatset features are mutually exclusive. Please enable only one of them."
);

#[cfg(feature = "set")]
use std::hash::{Hash, Hasher};

#[cfg(feature = "slimset")]
use std::collections::BTreeSet as Set;
#[cfg(feature = "fatset")]
use std::collections::HashSet as Set;

use anyhow::Result;
use tracing::{error, warn};

#[derive(Debug, Default)]
pub struct BlockFilter {
    #[cfg(feature = "bloom")]
    bloom: Option<bloomfilter::Bloom<str>>,
    #[cfg(feature = "set")]
    set: Set<u64>,
}

impl BlockFilter {
    #[cfg(feature = "bloom")]
    fn set_bloom(&mut self, bloom: Option<bloomfilter::Bloom<str>>) {
        self.bloom = bloom;
    }
    #[cfg(feature = "set")]
    fn set_set(&mut self, set: Set<u64>) {
        self.set = set;
    }
    #[cfg(feature = "bloom")]
    pub fn bloom_contains(&self, domain: &str) -> bool {
        self.bloom.as_ref().is_some_and(|bloom| bloom.check(domain))
    }
    #[cfg(feature = "set")]
    pub fn set_contains(&self, name: &str) -> bool {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        name.hash(&mut hasher);
        let val = hasher.finish();
        self.set.contains(&val)
    }

    #[allow(unreachable_code)]
    pub fn contains(&self, domain: &str) -> bool {
        #[cfg(feature = "bloom")]
        if !self.bloom_contains(domain) {
            return false;
        }

        #[cfg(feature = "set")]
        return self.set_contains(domain);

        true
    }

    #[allow(unreachable_code)]
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "bloom")]
        return self.bloom.is_none();

        #[cfg(feature = "set")]
        return self.set.is_empty();
    }
}

#[derive(Default, Debug)]
pub struct BlocklistBuilder(std::collections::HashSet<String>);

impl BlocklistBuilder {
    // set all the items in a blocklist file
    pub fn set_file(&mut self, block_file: &str) -> Result<()> {
        let file = std::fs::read_to_string(block_file)?;
        for line in file.lines() {
            self.set_item(line);
        }
        Ok(())
    }

    // set an individual item in the blocklist
    pub fn set_item(&mut self, item: &str) {
        let item = item.trim();
        if item.is_empty() {
        } else if let Some(name) = item.strip_prefix("*.") {
            self.0.insert(name.into());
        } else {
            self.0.insert(item.into());
        }
    }

    pub fn build(self) -> BlockFilter {
        if self.0.is_empty() {
            warn!("Blocklist Size 0");
            BlockFilter::default()
        } else {
            let mut block_filter = BlockFilter::default();

            #[cfg(feature = "set")]
            {
                let block_coll = self
                    .0
                    .iter()
                    .map(|s| {
                        // Hash the string to a u64 for use in the Set
                        let mut hasher = std::collections::hash_map::DefaultHasher::new();
                        s.hash(&mut hasher);
                        hasher.finish()
                    })
                    .collect();
                block_filter.set_set(block_coll);
            }

            #[cfg(feature = "bloom")]
            {
                let bloom = bloomfilter::Bloom::new_for_fp_rate(self.0.len(), 0.00001).map_or_else(
                |e| {
                    error!(
                        "Failed to create bloom filter for blocklist - {e}: blocklist inoperable"
                    );
                    None
                },
                |mut filter| {
                    for item in &self.0 {
                        filter.set(item.as_str());
                    }
                    Some(filter)
                });
                block_filter.set_bloom(bloom);
            }
            block_filter
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn contains(&self, domain: &str) -> bool {
        self.0.contains(domain)
    }

    #[cfg(test)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[cfg(test)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<String>> for BlocklistBuilder {
    fn from(block_files: Vec<String>) -> Self {
        let mut builder = Self::default();
        for block_file in &block_files {
            if let Err(e) = builder.set_file(block_file) {
                error!("Failed to load blocklist file {block_file}: {e}");
            }
        }
        builder
    }
}

impl From<Option<Vec<String>>> for BlocklistBuilder {
    fn from(block_files: Option<Vec<String>>) -> Self {
        let Some(blocklists) = block_files else {
            warn!("No blocklists defined in config");
            return Self::default();
        };
        Self::from(blocklists)
    }
}
