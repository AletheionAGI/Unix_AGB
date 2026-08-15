use crate::contracts::SecurityEvent;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub struct CanonicalStore {
    path: PathBuf,
    seen_ids: HashSet<String>,
    last_sequence: HashMap<String, u64>,
}

impl CanonicalStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        let mut store = Self {
            path,
            seen_ids: HashSet::new(),
            last_sequence: HashMap::new(),
        };
        if store.path.exists() {
            let file = File::open(&store.path).map_err(|e| e.to_string())?;
            for (index, line) in BufReader::new(file).lines().enumerate() {
                let line = line.map_err(|e| e.to_string())?;
                if line.trim().is_empty() {
                    continue;
                }
                let event: SecurityEvent = serde_json::from_str(&line)
                    .map_err(|e| format!("invalid canonical record at line {}: {e}", index + 1))?;
                store.index(&event)?;
            }
        }
        Ok(store)
    }

    fn index(&mut self, event: &SecurityEvent) -> Result<(), String> {
        if !self.seen_ids.insert(event.event_id.clone()) {
            return Err(format!("duplicate event_id: {}", event.event_id));
        }
        if let Some(last) = self.last_sequence.get(&event.namespace_id) {
            if event.sequence <= *last {
                return Err(format!(
                    "sequence replay for {}: {} <= {}",
                    event.namespace_id, event.sequence, last
                ));
            }
        }
        self.last_sequence
            .insert(event.namespace_id.clone(), event.sequence);
        Ok(())
    }

    pub fn append(&mut self, event: &SecurityEvent) -> Result<(), String> {
        event.validate()?;
        self.index(event)?;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        serde_json::to_writer(&mut file, event).map_err(|e| e.to_string())?;
        file.write_all(b"\n").map_err(|e| e.to_string())?;
        file.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn event_count(&self) -> usize {
        self.seen_ids.len()
    }

    pub fn namespace_count(&self) -> usize {
        self.last_sequence.len()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::sample_event;

    #[test]
    fn rejects_duplicate_and_sequence_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut store = CanonicalStore::open(&path).unwrap();
        let first = sample_event("evt:1", 1, 7, 100);
        store.append(&first).unwrap();
        assert!(store.append(&first).unwrap_err().contains("duplicate"));
        let replay = sample_event("evt:2", 1, 7, 100);
        assert!(
            store
                .append(&replay)
                .unwrap_err()
                .contains("sequence replay")
        );
    }

    #[test]
    fn exact_namespace_isolation_keeps_independent_sequences() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut store = CanonicalStore::open(&path).unwrap();
        store.append(&sample_event("evt:a", 1, 7, 100)).unwrap();
        store.append(&sample_event("evt:b", 1, 7, 200)).unwrap();
        assert_eq!(store.namespace_count(), 2);
    }
}
