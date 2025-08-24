use std::hash::{Hash, Hasher};

use std::collections::HashSet;

use anyhow::Result;
use tracing::{error, warn};

#[derive(Debug, Default)]
pub struct BlockFilter {
    set: HashSet<u64>,
}

impl BlockFilter {
    fn set_set(&mut self, set: HashSet<u64>) {
        self.set = set;
    }
    pub fn set_contains(&self, name: &str) -> bool {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        name.hash(&mut hasher);
        let val = hasher.finish();
        self.set.contains(&val)
    }

    pub fn contains(&self, domain: &str) -> bool {
        self.set_contains(domain)
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
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
