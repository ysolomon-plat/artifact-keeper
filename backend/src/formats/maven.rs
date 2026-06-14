//! Maven format handler.
//!
//! Implements Maven 2 repository layout and metadata parsing.

use async_trait::async_trait;
use bytes::Bytes;
use quick_xml::de::from_str;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Maven format handler
pub struct MavenHandler;

impl MavenHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Maven coordinates from path
    /// Path format: groupId/artifactId/version/artifactId-version[-classifier].extension
    pub fn parse_coordinates(path: &str) -> Result<MavenCoordinates> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        if parts.len() < 4 {
            return Err(AppError::Validation(
                "Invalid Maven path: expected groupId/artifactId/version/filename".to_string(),
            ));
        }

        let filename = parts[parts.len() - 1];
        let version = parts[parts.len() - 2];
        let artifact_id = parts[parts.len() - 3];
        let group_id = parts[..parts.len() - 3].join(".");

        // Parse filename to extract classifier and extension
        let (classifier, extension) = Self::parse_filename(filename, artifact_id, version)?;

        Ok(MavenCoordinates {
            group_id,
            artifact_id: artifact_id.to_string(),
            version: version.to_string(),
            classifier,
            extension,
        })
    }

    fn parse_filename(
        filename: &str,
        artifact_id: &str,
        version: &str,
    ) -> Result<(Option<String>, String)> {
        let expected_prefix = format!("{}-{}", artifact_id, version);

        // sbt cross-versioned plugins use artifact IDs like `sbt-foo_2.12_1.0` (from the
        // directory) but publish filenames in short form: `sbt-foo-2.0.4.jar`. Strip up to
        // two trailing `_segment` components where each looks like a version (has `.` or
        // starts with a digit), giving the short base name.
        let looks_like_version =
            |s: &str| s.contains('.') || s.chars().next().map_or(false, |c| c.is_ascii_digit());
        let short_base: Option<&str> = artifact_id.rfind('_').and_then(|i| {
            if looks_like_version(&artifact_id[i + 1..]) {
                let after = &artifact_id[..i];
                Some(
                    after
                        .rfind('_')
                        .filter(|&j| looks_like_version(&after[j + 1..]))
                        .map_or(after, |j| &after[..j]),
                )
            } else {
                None
            }
        });

        let base_version = version.strip_suffix("-SNAPSHOT");
        let snapshot_prefix = base_version.map(|bv| format!("{}-{}", artifact_id, bv));
        let short_prefix = short_base.map(|sb| format!("{}-{}", sb, version));
        let short_snapshot_prefix = short_base
            .zip(base_version)
            .map(|(sb, bv)| format!("{}-{}", sb, bv));

        let is_metadata = |f: &str| {
            f == "maven-metadata.xml"
                || f.ends_with(".md5")
                || f.ends_with(".sha1")
                || f.ends_with(".sha256")
                || f.ends_with(".sha512")
        };
        let validation_err = || {
            Err(AppError::Validation(format!(
                "Invalid Maven filename: expected to start with {}",
                expected_prefix
            )))
        };

        let mut is_snapshot_timestamp = false;
        // Try prefixes in priority order using a labeled block.
        // `short_prefix` uses the full version (including -SNAPSHOT) so it matches the exact-SNAPSHOT
        // short form (`sbt-foo-2.0.4-SNAPSHOT.jar`) before `short_snapshot_prefix` can misparse
        // `-SNAPSHOT` as a classifier.
        let remainder: &str = 'find: {
            if filename.starts_with(&expected_prefix) {
                break 'find &filename[expected_prefix.len()..];
            }
            if let Some(ref snap) = snapshot_prefix {
                if filename.starts_with(snap.as_str()) {
                    let rem = &filename[snap.len()..];
                    let stripped = Self::strip_snapshot_timestamp(rem);
                    is_snapshot_timestamp = stripped != rem;
                    break 'find stripped;
                }
            }
            if let Some(ref spfx) = short_prefix {
                if filename.starts_with(spfx.as_str()) {
                    break 'find &filename[spfx.len()..];
                }
            }
            if let Some(ref ssnap) = short_snapshot_prefix {
                if filename.starts_with(ssnap.as_str()) {
                    let rem = &filename[ssnap.len()..];
                    let stripped = Self::strip_snapshot_timestamp(rem);
                    is_snapshot_timestamp = stripped != rem;
                    break 'find stripped;
                }
            }
            if is_metadata(filename) {
                return Ok((None, filename.to_string()));
            }
            return validation_err();
        };

        if remainder.is_empty() {
            return Err(AppError::Validation(
                "Invalid Maven filename: missing extension".to_string(),
            ));
        }

        // `is_snapshot_timestamp` is only set when strip_snapshot_timestamp actually removed
        // a timestamp suffix. If not set, `-SNAPSHOT` in the remainder is a classifier (#1399).
        let _ = is_snapshot_timestamp; // consumed above; kept for clarity

        // Classifier: -classifier.ext (empty classifier is not valid — see #1399).
        if let Some(rest) = remainder.strip_prefix('-') {
            if let Some(dot_pos) = rest.rfind('.') {
                let classifier = &rest[..dot_pos];
                let extension = &rest[dot_pos + 1..];
                if !classifier.is_empty() {
                    return Ok((Some(classifier.to_string()), extension.to_string()));
                }
            }
        }

        // No classifier: .ext
        if let Some(ext) = remainder.strip_prefix('.') {
            return Ok((None, ext.to_string()));
        }

        Err(AppError::Validation(
            "Invalid Maven filename format".to_string(),
        ))
    }

    /// Strip `-YYYYMMDD.HHMMSS-N` from the start of `remainder`. Returns input unchanged on mismatch.
    fn strip_snapshot_timestamp(remainder: &str) -> &str {
        let b = remainder.as_bytes();
        if b.len() < 18
            || b[0] != b'-'
            || !b[1..9].iter().all(u8::is_ascii_digit)
            || b[9] != b'.'
            || !b[10..16].iter().all(u8::is_ascii_digit)
            || b[16] != b'-'
        {
            return remainder;
        }
        let end = b[17..]
            .iter()
            .position(|c| !c.is_ascii_digit())
            .map_or(b.len(), |p| 17 + p);
        if end == 17 {
            remainder
        } else {
            &remainder[end..]
        }
    }

    /// Check if this is a POM file
    pub fn is_pom(path: &str) -> bool {
        path.ends_with(".pom") || path.ends_with("/pom.xml")
    }

    /// Check if this is a metadata file
    pub fn is_metadata(path: &str) -> bool {
        path.ends_with("maven-metadata.xml")
    }

    /// Parse POM file
    pub fn parse_pom(content: &[u8]) -> Result<PomProject> {
        let content_str = std::str::from_utf8(content)
            .map_err(|e| AppError::Validation(format!("Invalid UTF-8 in POM: {}", e)))?;

        from_str(content_str).map_err(|e| AppError::Validation(format!("Invalid POM XML: {}", e)))
    }
}

impl Default for MavenHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for MavenHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Maven
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let coords = Self::parse_coordinates(path)?;

        let mut metadata = serde_json::json!({
            "groupId": coords.group_id,
            "artifactId": coords.artifact_id,
            "version": coords.version,
            "extension": coords.extension,
        });

        if let Some(classifier) = &coords.classifier {
            metadata["classifier"] = serde_json::Value::String(classifier.clone());
        }

        // If it's a POM, parse additional metadata
        if Self::is_pom(path) {
            if let Ok(pom) = Self::parse_pom(content) {
                if let Some(name) = pom.name {
                    metadata["name"] = serde_json::Value::String(name);
                }
                if let Some(description) = pom.description {
                    metadata["description"] = serde_json::Value::String(description);
                }
                if let Some(url) = pom.url {
                    metadata["url"] = serde_json::Value::String(url);
                }
                if let Some(deps) = pom.dependencies {
                    metadata["dependencies"] = serde_json::to_value(deps.dependency)
                        .unwrap_or(serde_json::Value::Array(vec![]));
                }
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        // Validate coordinates can be parsed
        let _coords = Self::parse_coordinates(path)?;

        // Validate POM if applicable
        if Self::is_pom(path) {
            let _pom = Self::parse_pom(content)?;
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Maven uses maven-metadata.xml which is generated per artifact
        // This would typically be generated on demand based on DB state
        Ok(None)
    }
}

/// Maven coordinates (GAV)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavenCoordinates {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub classifier: Option<String>,
    pub extension: String,
}

impl MavenCoordinates {
    /// Get the repository path for these coordinates
    pub fn to_path(&self, filename: &str) -> String {
        format!(
            "{}/{}/{}/{}",
            self.group_id.replace('.', "/"),
            self.artifact_id,
            self.version,
            filename
        )
    }

    /// Get the standard filename for these coordinates
    pub fn filename(&self) -> String {
        match &self.classifier {
            Some(c) => format!(
                "{}-{}-{}.{}",
                self.artifact_id, self.version, c, self.extension
            ),
            None => format!("{}-{}.{}", self.artifact_id, self.version, self.extension),
        }
    }
}

/// POM project model (simplified)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PomProject {
    pub model_version: Option<String>,
    pub group_id: Option<String>,
    pub artifact_id: Option<String>,
    pub version: Option<String>,
    pub packaging: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub parent: Option<PomParent>,
    pub dependencies: Option<PomDependencies>,
    /// Maven `<properties>` as a flat `name -> value` map. Deserialized
    /// directly into a map: quick-xml treats the arbitrary-named child
    /// elements of `<properties>` as map entries. (A `#[serde(flatten)]`
    /// wrapper struct fails here with "invalid type: map, expected a
    /// string", which previously made any POM declaring `<properties>`
    /// unparseable.)
    pub properties: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PomParent {
    pub group_id: Option<String>,
    pub artifact_id: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PomDependencies {
    #[serde(default)]
    pub dependency: Vec<PomDependency>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PomDependency {
    pub group_id: String,
    pub artifact_id: String,
    pub version: Option<String>,
    pub scope: Option<String>,
    #[serde(rename = "type")]
    pub dep_type: Option<String>,
    pub classifier: Option<String>,
    pub optional: Option<String>,
}

/// Generate maven-metadata.xml content
pub fn generate_metadata_xml(
    group_id: &str,
    artifact_id: &str,
    versions: &[String],
    latest: &str,
    release: Option<&str>,
) -> String {
    let mut versions_xml = String::new();
    for v in versions {
        versions_xml.push_str(&format!("      <version>{}</version>\n", v));
    }

    let release_line = match release {
        Some(r) => format!("    <release>{}</release>\n", r),
        None => String::new(),
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>{}</groupId>
  <artifactId>{}</artifactId>
  <versioning>
    <latest>{}</latest>
{}    <versions>
{}    </versions>
    <lastUpdated>{}</lastUpdated>
  </versioning>
</metadata>
"#,
        group_id,
        artifact_id,
        latest,
        release_line,
        versions_xml,
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    )
}

/// Parse a maven-metadata.xml to extract the version list.
/// Returns (groupId, artifactId, versions).
pub fn parse_metadata_versions(xml: &str) -> Option<(String, String, Vec<String>)> {
    let group_id = xml
        .split("<groupId>")
        .nth(1)?
        .split("</groupId>")
        .next()?
        .to_string();
    let artifact_id = xml
        .split("<artifactId>")
        .nth(1)?
        .split("</artifactId>")
        .next()?
        .to_string();

    let mut versions = Vec::new();
    if let Some(versions_block) = xml.split("<versions>").nth(1) {
        if let Some(versions_block) = versions_block.split("</versions>").next() {
            for segment in versions_block.split("<version>").skip(1) {
                if let Some(ver) = segment.split("</version>").next() {
                    let ver = ver.trim();
                    if !ver.is_empty() {
                        versions.push(ver.to_string());
                    }
                }
            }
        }
    }

    Some((group_id, artifact_id, versions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_coordinates() {
        let coords = MavenHandler::parse_coordinates(
            "org/apache/maven/maven-core/3.8.1/maven-core-3.8.1.jar",
        )
        .unwrap();
        assert_eq!(coords.group_id, "org.apache.maven");
        assert_eq!(coords.artifact_id, "maven-core");
        assert_eq!(coords.version, "3.8.1");
        assert_eq!(coords.classifier, None);
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_coordinates_with_classifier() {
        let coords = MavenHandler::parse_coordinates(
            "org/apache/maven/maven-core/3.8.1/maven-core-3.8.1-sources.jar",
        )
        .unwrap();
        assert_eq!(coords.group_id, "org.apache.maven");
        assert_eq!(coords.artifact_id, "maven-core");
        assert_eq!(coords.version, "3.8.1");
        assert_eq!(coords.classifier, Some("sources".to_string()));
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_pom_coordinates() {
        let coords =
            MavenHandler::parse_coordinates("com/example/mylib/1.0.0/mylib-1.0.0.pom").unwrap();
        assert_eq!(coords.group_id, "com.example");
        assert_eq!(coords.artifact_id, "mylib");
        assert_eq!(coords.version, "1.0.0");
        assert_eq!(coords.extension, "pom");
    }

    #[test]
    fn test_parse_pom_with_properties_and_dependencies() {
        // Regression: a POM declaring <properties> previously failed to parse
        // entirely ("invalid type: map, expected a string"), which made
        // validate() reject such uploads and left the SBOM without declared
        // dependencies (#870). Real-world POMs almost always declare
        // properties, so this must parse.
        let pom = b"<project>\
            <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>\
            <properties>\
                <java.version>17</java.version>\
                <guava.version>32.1.3-jre</guava.version>\
            </properties>\
            <dependencies>\
                <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>${guava.version}</version></dependency>\
            </dependencies>\
        </project>";
        let parsed = MavenHandler::parse_pom(pom).expect("POM with <properties> must parse");
        let props = parsed.properties.expect("properties present");
        assert_eq!(props.get("java.version").map(|s| s.as_str()), Some("17"));
        assert_eq!(
            props.get("guava.version").map(|s| s.as_str()),
            Some("32.1.3-jre")
        );
        let deps = parsed.dependencies.expect("dependencies present");
        assert_eq!(deps.dependency.len(), 1);
        assert_eq!(deps.dependency[0].artifact_id, "guava");
    }

    #[test]
    fn test_coordinates_to_path() {
        let coords = MavenCoordinates {
            group_id: "com.example".to_string(),
            artifact_id: "mylib".to_string(),
            version: "1.0.0".to_string(),
            classifier: None,
            extension: "jar".to_string(),
        };
        assert_eq!(
            coords.to_path("mylib-1.0.0.jar"),
            "com/example/mylib/1.0.0/mylib-1.0.0.jar"
        );
    }

    #[test]
    fn test_parse_snapshot_coordinates() {
        // SNAPSHOT version with exact -SNAPSHOT filename
        let coords = MavenHandler::parse_coordinates(
            "com/example/test/1.0.0-SNAPSHOT/test-1.0.0-SNAPSHOT.jar",
        )
        .unwrap();
        assert_eq!(coords.group_id, "com.example");
        assert_eq!(coords.artifact_id, "test");
        assert_eq!(coords.version, "1.0.0-SNAPSHOT");
        assert_eq!(coords.classifier, None);
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_snapshot_timestamp_coordinates() {
        // SNAPSHOT version with timestamp-resolved filename (Maven deploy format)
        // The timestamp-build suffix should NOT be treated as a classifier.
        let coords = MavenHandler::parse_coordinates(
            "com/example/test/1.0.0-SNAPSHOT/test-1.0.0-20260211.124623-1.jar",
        )
        .unwrap();
        assert_eq!(coords.group_id, "com.example");
        assert_eq!(coords.artifact_id, "test");
        assert_eq!(coords.version, "1.0.0-SNAPSHOT");
        assert_eq!(coords.classifier, None);
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_snapshot_timestamp_with_classifier() {
        // A timestamped SNAPSHOT with an actual classifier (sources/javadoc)
        let coords = MavenHandler::parse_coordinates(
            "com/example/test/1.2.3-SNAPSHOT/test-1.2.3-20260211.124623-1-sources.jar",
        )
        .unwrap();
        assert_eq!(coords.artifact_id, "test");
        assert_eq!(coords.version, "1.2.3-SNAPSHOT");
        assert_eq!(coords.classifier, Some("sources".to_string()));
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_strip_snapshot_timestamp() {
        assert_eq!(
            MavenHandler::strip_snapshot_timestamp("-20260314.155654-1.jar"),
            ".jar"
        );
        assert_eq!(
            MavenHandler::strip_snapshot_timestamp("-20260314.155654-1-sources.jar"),
            "-sources.jar"
        );
        assert_eq!(
            MavenHandler::strip_snapshot_timestamp("-20260314.155654-12.pom"),
            ".pom"
        );
        // Non-timestamp remainders returned unchanged
        assert_eq!(
            MavenHandler::strip_snapshot_timestamp("-sources.jar"),
            "-sources.jar"
        );
        assert_eq!(MavenHandler::strip_snapshot_timestamp(".jar"), ".jar");
    }

    #[test]
    fn test_parse_snapshot_pom() {
        let coords = MavenHandler::parse_coordinates(
            "com/example/test/1.0.0-SNAPSHOT/test-1.0.0-20260211.124623-1.pom",
        )
        .unwrap();
        assert_eq!(coords.artifact_id, "test");
        assert_eq!(coords.version, "1.0.0-SNAPSHOT");
        assert_eq!(coords.extension, "pom");
    }

    #[test]
    fn test_parse_coordinates_rejects_empty_classifier() {
        // `artifact-version-.ext` has a dangling hyphen and an empty
        // classifier. It is not a valid Maven coordinate; the parser
        // must reject it rather than returning `Some("")`. The Maven
        // virtual-repo fallback (#1399) relies on this to refuse routing
        // empty-classifier paths around their SQL row.
        let result = MavenHandler::parse_coordinates("g/a/1.0/a-1.0-.jar");
        assert!(
            result.is_err(),
            "empty-classifier coordinate must not parse as a valid Maven path"
        );
    }

    #[test]
    fn test_parse_snapshot_metadata() {
        // maven-metadata.xml in a SNAPSHOT version directory should still work
        let coords =
            MavenHandler::parse_coordinates("com/example/test/1.0.0-SNAPSHOT/maven-metadata.xml")
                .unwrap();
        assert_eq!(coords.artifact_id, "test");
        assert_eq!(coords.version, "1.0.0-SNAPSHOT");
        assert_eq!(coords.extension, "maven-metadata.xml");
    }

    #[test]
    fn test_generate_metadata() {
        let xml = generate_metadata_xml(
            "com.example",
            "mylib",
            &["1.0.0".to_string(), "1.1.0".to_string()],
            "1.1.0",
            Some("1.1.0"),
        );
        assert!(xml.contains("<groupId>com.example</groupId>"));
        assert!(xml.contains("<artifactId>mylib</artifactId>"));
        assert!(xml.contains("<latest>1.1.0</latest>"));
        assert!(xml.contains("<release>1.1.0</release>"));
    }

    #[test]
    fn test_parse_metadata_versions() {
        let xml = generate_metadata_xml(
            "com.example",
            "my-lib",
            &["1.0.0".into(), "1.1.0".into()],
            "1.1.0",
            Some("1.1.0"),
        );
        let (g, a, versions) = parse_metadata_versions(&xml).unwrap();
        assert_eq!(g, "com.example");
        assert_eq!(a, "my-lib");
        assert_eq!(versions, vec!["1.0.0", "1.1.0"]);
    }

    #[test]
    fn test_parse_sbt_plugin_short_filename() {
        // sbt plugins publish under `artifact_2.12_1.0/` but use a short filename.
        let coords = MavenHandler::parse_coordinates(
            "com/example/sbt-foo_2.12_1.0/2.0.4/sbt-foo-2.0.4.jar",
        )
        .unwrap();
        assert_eq!(coords.artifact_id, "sbt-foo_2.12_1.0");
        assert_eq!(coords.version, "2.0.4");
        assert_eq!(coords.classifier, None);
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_sbt_plugin_single_underscore() {
        // Plugins with only one underscore (e.g. scala-version only) must also work.
        let coords = MavenHandler::parse_coordinates(
            "com/example/sbt-foo_2.12/2.0.4/sbt-foo-2.0.4.jar",
        )
        .unwrap();
        assert_eq!(coords.artifact_id, "sbt-foo_2.12");
        assert_eq!(coords.classifier, None);
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_sbt_plugin_snapshot_timestamp() {
        // sbt plugin SNAPSHOT with a timestamp filename.
        let coords = MavenHandler::parse_coordinates(
            "com/example/sbt-foo_2.12_1.0/2.0.4-SNAPSHOT/sbt-foo-2.0.4-20240101.120000-3.jar",
        )
        .unwrap();
        assert_eq!(coords.artifact_id, "sbt-foo_2.12_1.0");
        assert_eq!(coords.version, "2.0.4-SNAPSHOT");
        assert_eq!(coords.classifier, None);
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_sbt_plugin_exact_snapshot_not_misclassified() {
        // Exact-SNAPSHOT filename (`sbt-foo-2.0.4-SNAPSHOT.jar`) must NOT parse
        // `-SNAPSHOT` as a classifier — it should be a no-classifier `.jar`.
        let coords = MavenHandler::parse_coordinates(
            "com/example/sbt-foo_2.12_1.0/2.0.4-SNAPSHOT/sbt-foo-2.0.4-SNAPSHOT.jar",
        )
        .unwrap();
        assert_eq!(coords.classifier, None);
        assert_eq!(coords.extension, "jar");
    }
}
