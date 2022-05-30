```rust
/// An Artifacts implementation that uses a compact representation
///
/// Creates a single json artifact with
/// ```json
///  {
///    "abi": [],
///    "bin": "...",
///    "runtime-bin": "..."
///  }
/// ```
/// A `CacheEntry` in the cache file represents a solidity file
///
/// A solidity file can contain several contracts, for every contract a separate `Artifact` is
/// emitted. so the `CacheEntry` tracks the artifacts by name. A file can be compiled with multiple
/// `solc` versions generating version specific artifacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntry {
    /// the last modification time of this file
    pub last_modification_date: u64,
    /// hash to identify whether the content of the file changed
    pub content_hash: String,
    /// identifier name see [`crate::util::source_name()`]
    pub source_name: PathBuf,
    /// what config was set when compiling this file
    pub solc_config: SolcConfig,
    /// fully resolved imports of the file
    ///
    /// all paths start relative from the project's root: `src/importedFile.sol`
    pub imports: BTreeSet<PathBuf>,
    /// The solidity version pragma
    pub version_requirement: Option<String>,
    /// all artifacts produced for this file
    ///
    /// In theory a file can be compiled by different solc versions:
    /// `A(<=0.8.10) imports C(>0.4.0)` and `B(0.8.11) imports C(>0.4.0)`
    /// file `C` would be compiled twice, with `0.8.10` and `0.8.11`, producing two different
    /// artifacts.
    ///
    /// This map tracks the artifacts by `name -> (Version -> PathBuf)`.
    /// This mimics the default artifacts directory structure
    pub artifacts: BTreeMap<String, BTreeMap<Version, PathBuf>>,
        /// the project
    pub project: &'a Project<T>,
    /// all files that were filtered because they haven't changed
    pub filtered: HashMap<PathBuf, (Source, HashSet<Version>)>,
    /// the corresponding cache entries for all sources that were deemed to be dirty
    ///
    /// `CacheEntry` are grouped by their solidity file.
    /// During preprocessing the `artifacts` field of a new `CacheEntry` is left blank, because in
    /// order to determine the artifacts of the solidity file, the file needs to be compiled first.
    /// Only after the `CompilerOutput` is received and all compiled contracts are handled, see
    /// [`crate::ArtifactOutput::on_output()`] all artifacts, their disk paths, are determined and
    /// can be populated before the updated [`crate::SolFilesCache`] is finally written to disk,
    /// see [`Cache::finish()`]
    pub dirty_entries: HashMap<PathBuf, (CacheEntry, HashSet<Version>)>,
    /// the file hashes
    pub content_hashes: HashMap<PathBuf, String>,
}

impl<'a, T: ArtifactOutput> ArtifactsCacheInner<'a, T> {
    /// Creates a new cache entry for the file
    fn create_cache_entry(&self, file: &Path, source: &Source) -> CacheEntry {
        let imports = self
            .edges
            .imports(file)
            .into_iter()
            .map(|import| utils::source_name(import, self.project.root()).to_path_buf())
            .collect();

        let entry = CacheEntry {
            last_modification_date: CacheEntry::read_last_modification_date(&file)
                .unwrap_or_default(),
            content_hash: source.content_hash(),
            source_name: utils::source_name(file, self.project.root()).into(),
            solc_config: self.project.solc_config.clone(),
            imports,
            version_requirement: self.edges.version_requirement(file).map(|v| v.to_string()),
            // artifacts remain empty until we received the compiler output
            artifacts: Default::default(),
        };

        entry
    }

    /// inserts a new cache entry for the given file
    ///
    /// If there is already an entry available for the file the given version is added to the set
    fn insert_new_cache_entry(&mut self, file: &Path, source: &Source, version: Version) {
        if let Some((_, versions)) = self.dirty_entries.get_mut(file) {
            versions.insert(version);
        } else {
            let entry = self.create_cache_entry(file, source);
            self.dirty_entries.insert(file.to_path_buf(), (entry, HashSet::from([version])));
        }
    }

    /// inserts the filtered source with the fiven version
    fn insert_filtered_source(&mut self, file: PathBuf, source: Source, version: Version) {
        match self.filtered.entry(file) {
            hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().1.insert(version);
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert((source, HashSet::from([version])));
            }
        }
    }

    /// Returns only those sources that
    ///   - are new
    ///   - were changed
    ///   - their imports were changed
    ///   - their artifact is missing
    fn filter(&mut self, sources: Sources, version: &Version) -> Sources {
        self.fill_hashes(&sources);
        sources
            .into_iter()
            .filter_map(|(file, source)| self.requires_solc(file, source, version))
            .collect()
    }

    /// Returns `Some` if the file _needs_ to be compiled and `None` if the artifact can be reu-used
    fn requires_solc(
        &mut self,
        file: PathBuf,
        source: Source,
        version: &Version,
    ) -> Option<(PathBuf, Source)> {
        if !self.is_dirty(&file, version) &&
            self.edges.imports(&file).iter().all(|file| !self.is_dirty(file, version))
        {
            self.insert_filtered_source(file, source, version.clone());
            None
        } else {
            self.insert_new_cache_entry(&file, &source, version.clone());

            Some((file, source))
        }
    }

    /// returns `false` if the corresponding cache entry remained unchanged otherwise `true`
    fn is_dirty(&self, file: &Path, version: &Version) -> bool {
        if let Some(hash) = self.content_hashes.get(file) {
            if let Some(entry) = self.cache.entry(&file) {
                if entry.content_hash.as_bytes() != hash.as_bytes() {
                    tracing::trace!(
                        "changed content hash for cached artifact \"{}\"",
                        file.display()
                    );
                    return true
                }
                if self.project.solc_config != entry.solc_config {
                    tracing::trace!(
                        "changed solc config for cached artifact \"{}\"",
                        file.display()
                    );
                    return true
                }

                if !entry.contains_version(version) {
                    tracing::trace!("missing linked artifacts for version \"{}\"", version);
                    return true
                }

                if entry.artifacts_for_version(version).any(|artifact_path| {
                    let missing_artifact = !self.cached_artifacts.has_artifact(artifact_path);
                    if missing_artifact {
                        tracing::trace!("missing artifact \"{}\"", artifact_path.display());
                    }
                    missing_artifact
                }) {
                    return true
                }
                // all things match, can be reused
                return false
            }
            tracing::trace!("Missing cache entry for {}", file.display());
        }
        true
    }

    /// Adds the file's hashes to the set if not set yet
    fn fill_hashes(&mut self, sources: &Sources) {
        for (file, source) in sources {
            if let hash_map::Entry::Vacant(entry) = self.content_hashes.entry(file.clone()) {
                entry.insert(source.content_hash());
            }
        }
    }
}

/// Abstraction over configured caching which can be either non-existent or an already loaded cache
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum ArtifactsCache<'a, T: ArtifactOutput> {
    /// Cache nothing on disk
    Ephemeral(GraphEdges, &'a Project<T>),
    /// Handles the actual cached artifacts, detects artifacts that can be reused
    Cached(ArtifactsCacheInner<'a, T>),
}

impl<'a, T: ArtifactOutput> ArtifactsCache<'a, T> {
    pub fn new(project: &'a Project<T>, edges: GraphEdges) -> Result<Self> {
        let cache = if project.cached {
            // read the cache file if it already exists
            let mut cache = if project.cache_path().exists() {
                SolFilesCache::read_joined(&project.paths).unwrap_or_default()
            } else {
                SolFilesCache::default()
            };

            cache.remove_missing_files();

            // read all artifacts
            let cached_artifacts = if project.paths.artifacts.exists() {
                tracing::trace!("reading artifacts from cache..");
                // if we failed to read the whole set of artifacts we use an empty set
                let artifacts = cache.read_artifacts::<T::Artifact>().unwrap_or_default();
                tracing::trace!("read {} artifacts from cache", artifacts.artifact_files().count());
                artifacts
            } else {
                Default::default()
            };

            let cache = ArtifactsCacheInner {
                cache,
                cached_artifacts,
                edges,
                project,
                filtered: Default::default(),
                dirty_entries: Default::default(),
                content_hashes: Default::default(),
            };

            ArtifactsCache::Cached(cache)
        } else {
            // nothing to cache
            ArtifactsCache::Ephemeral(edges, project)
        };

        Ok(cache)
    }

    #[cfg(test)]
    pub fn as_cached(&self) -> Option<&ArtifactsCacheInner<'a, T>> {
        match self {
            ArtifactsCache::Ephemeral(_, _) => None,
            ArtifactsCache::Cached(cached) => Some(cached),
        }
    }

    pub fn project(&self) -> &'a Project<T> {
        match self {
            ArtifactsCache::Ephemeral(_, project) => project,
            ArtifactsCache::Cached(cache) => cache.project,
        }
    }

    /// Filters out those sources that don't need to be compiled
    pub fn filter(&mut self, sources: Sources, version: &Version) -> Sources {
        match self {
            ArtifactsCache::Ephemeral(_, _) => sources,
            ArtifactsCache::Cached(cache) => cache.filter(sources, version),
        }
    }

    /// Consumes the `Cache`, rebuilds the [`SolFileCache`] by merging all artifacts that were
    /// filtered out in the previous step (`Cache::filtered`) and the artifacts that were just
    /// compiled and written to disk `written_artifacts`.
    ///
    /// Returns all the _cached_ artifacts.
    pub fn write_cache(
        self,
        written_artifacts: &Artifacts<T::Artifact>,
    ) -> Result<Artifacts<T::Artifact>> {
        match self {
            ArtifactsCache::Ephemeral(_, _) => Ok(Default::default()),
            ArtifactsCache::Cached(cache) => {
                let ArtifactsCacheInner {
                    mut cache,
                    mut cached_artifacts,
                    mut dirty_entries,
                    filtered,
                    project,
                    ..
                } = cache;

                // keep only those files that were previously filtered (not dirty, reused)
                cache.retain(filtered.iter().map(|(p, (_, v))| (p.as_path(), v)));

                // add the artifacts to the cache entries, this way we can keep a mapping from
                // solidity file to its artifacts
                // this step is necessary because the concrete artifacts are only known after solc
                // was invoked and received as output, before that we merely know the file and
                // the versions, so we add the artifacts on a file by file basis
                for (file, artifacts) in written_artifacts.as_ref() {
                    let file_path = Path::new(&file);
                    if let Some((entry, versions)) = dirty_entries.get_mut(file_path) {
                        entry.insert_artifacts(artifacts.iter().map(|(name, artifacts)| {
                            let artifacts = artifacts
                                .iter()
                                .filter(|artifact| versions.contains(&artifact.version))
                                .collect::<Vec<_>>();
                            (name, artifacts)
                        }));
                    }

                    // cached artifacts that were overwritten also need to be removed from the
                    // `cached_artifacts` set
                    if let Some((f, mut cached)) = cached_artifacts.0.remove_entry(file) {
                        cached.retain(|name, files| {
                            if let Some(written_files) = artifacts.get(name) {
                                files.retain(|f| {
                                    written_files.iter().all(|other| other.version != f.version)
                                });
                                return !files.is_empty()
                            }
                            false
                        });
                        if !cached.is_empty() {
                            cached_artifacts.0.insert(f, cached);
                        }
                    }
                }

                // add the new cache entries to the cache file
                cache.extend(dirty_entries.into_iter().map(|(file, (entry, _))| (file, entry)));

                cache.strip_artifact_files_prefixes(project.artifacts_path());
                // write to disk
                cache.write(project.cache_path())?;

                Ok(cached_artifacts)
            }
        }
```
https://github.com/gakonst/ethers-rs/pull/802/files#diff-8b131e9bf9b4c6f0c4f4ee201283159e1d8e5ce2f981013301fd002aaa5c0b89R514-R523

