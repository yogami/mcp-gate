//! YAML span map for locating AST keys and paths to line numbers.

use std::collections::HashMap;
use std::convert::Infallible;
use std::str::FromStr;

use saphyr::{LoadableYamlNode, MarkedYaml, YamlData};

#[derive(Debug, Clone, Default)]
pub struct SpanMap {
    spans: HashMap<String, u32>,
}

impl FromStr for SpanMap {
    type Err = Infallible;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let mut map = Self {
            spans: HashMap::new(),
        };

        if let Ok(docs) = MarkedYaml::load_from_str(src) {
            for doc in docs {
                map.walk_node(&doc, "");
            }
        }

        Ok(map)
    }
}

impl SpanMap {
    /// Parse YAML source text into a `SpanMap` indexing path locations by line number.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(src: &str) -> Self {
        <Self as FromStr>::from_str(src).unwrap()
    }

    /// Retrieve the 1-based line number for a configuration path.
    pub fn line_of(&self, path: &str) -> Option<u32> {
        self.spans.get(path).copied()
    }

    fn record(&mut self, path: String, line: usize) {
        if !path.is_empty() {
            self.spans.insert(path, line as u32);
        }
    }

    fn walk_node(&mut self, node: &MarkedYaml<'_>, prefix: &str) {
        match &node.data {
            YamlData::Mapping(mapping) => {
                for (key_node, val_node) in mapping.iter() {
                    let key_str = match &key_node.data {
                        YamlData::Value(saphyr::Scalar::String(s)) => s.as_ref(),
                        YamlData::Representation(s, ..) => s.as_ref(),
                        _ => continue,
                    };

                    let path = if prefix.is_empty() {
                        key_str.to_string()
                    } else {
                        format!("{prefix}.{key_str}")
                    };

                    self.record(path.clone(), key_node.span.start.line());
                    self.walk_node(val_node, &path);
                }
            }
            YamlData::Sequence(seq) => {
                for (idx, item) in seq.iter().enumerate() {
                    let item_path = format!("{prefix}[{idx}]");
                    self.record(item_path.clone(), item.span.start.line());
                    self.walk_node(item, &item_path);
                }
            }
            _ => {}
        }
    }
}
