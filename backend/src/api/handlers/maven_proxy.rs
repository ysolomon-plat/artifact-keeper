//! Maven-specific storage fallback for virtual-repo proxy downloads.
//! Handles GAV-grouped secondaries (`.pom`, checksums, classifier jars) and rowless primaries
//! while enforcing quarantine and soft-delete policy via a live sibling anchor row.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers::{
    check_quarantine_row, internal_error, LocalArtifactRow, StreamingFetchResult,
};
use crate::api::AppState;
use crate::formats::maven::MavenHandler;
use crate::storage::StorageLocation;

/// Known secondary suffixes. Primaries (`.jar`/`.aar`/etc.) are excluded — they go through Gate 1.
const MAVEN_SECONDARY_FILE_EXTENSIONS: &[&str] = &[
    ".pom",
    ".module",
    "-sources.jar",
    "-javadoc.jar",
    "-tests.jar",
    "-test-sources.jar",
    ".sha1",
    ".sha256",
    ".sha512",
    ".md5",
    ".asc",
];

#[inline]
fn is_maven_secondary_path(path: &str) -> bool {
    if MAVEN_SECONDARY_FILE_EXTENSIONS
        .iter()
        .any(|ext| path.ends_with(ext))
    {
        return true;
    }

    MavenHandler::parse_coordinates(path)
        .map(|coords| coords.classifier.is_some())
        .unwrap_or(false)
}

/// Primary artifact extensions eligible for the storage fallback when a live sibling anchors the GAV.
const MAVEN_PRIMARY_FILE_EXTENSIONS: &[&str] = &[".jar", ".aar", ".war", ".ear", ".zip"];

/// Returns `true` when `path` ends with a primary extension. Caller must pre-compute `is_secondary`
/// and only call this when `!is_secondary` to avoid running `parse_coordinates` twice.
#[inline]
fn is_maven_primary_path_given_not_secondary(path: &str) -> bool {
    MAVEN_PRIMARY_FILE_EXTENSIONS
        .iter()
        .any(|ext| path.ends_with(ext))
}

/// Escape SQL LIKE metacharacters so sbt artifact IDs (e.g. `sbt-foo_2.12_1.0`) don't wildcard-match siblings.
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

/// Derive the GAV directory prefix for a maven artifact path.
///
fn maven_gav_directory(artifact_path: &str) -> Option<&str> {
    artifact_path.rsplit_once('/').map(|(dir, _)| dir)
}

/// Storage-direct fallback for virtual-repo Maven downloads.
/// Secondaries (`.pom`, checksums, `-sources.jar`) have no DB row so `local_fetch_by_path` returns
/// 404; this helper reads them from storage while enforcing quarantine/soft-delete via a sibling row.
/// Rowless primaries (`.jar`/`.aar`) whose GAV is anchored by a live `.pom` are also served here.
pub(crate) async fn maven_local_fetch_storage_fallback(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    artifact_path: &str,
) -> Result<StreamingFetchResult, Response> {
    // Gate 1: Only secondaries and bare primaries are eligible; anything else is 404.
    let is_secondary = is_maven_secondary_path(artifact_path);
    let is_primary = !is_secondary && is_maven_primary_path_given_not_secondary(artifact_path);
    if !is_secondary && !is_primary {
        return Err((StatusCode::NOT_FOUND, "Artifact not found").into_response());
    }

    // Gate 1.5: Reject primaries whose own row is soft-deleted (artifact was retracted).
    if is_primary {
        let own_is_deleted = sqlx::query_scalar::<_, bool>(
            "SELECT is_deleted FROM artifacts WHERE repository_id = $1 AND path = $2 LIMIT 1",
        )
        .bind(repo_id)
        .bind(artifact_path)
        .fetch_optional(db)
        .await
        .map_err(|e| internal_error("Database", e))?;

        if own_is_deleted == Some(true) {
            return Err((StatusCode::NOT_FOUND, "Artifact not found").into_response());
        }
    }

    // Gate 2: Require a live sibling in the same GAV directory as the anchor.
    // Prefer primary-extension rows so quarantine is checked against the authoritative row.
    // Escape LIKE metacharacters — sbt artifact IDs contain `_` which is a wildcard.
    let gav_dir = match maven_gav_directory(artifact_path) {
        Some(dir) if !dir.is_empty() => dir,
        _ => return Err((StatusCode::NOT_FOUND, "Artifact not found").into_response()),
    };
    let sibling_like = format!("{}/", escape_like(gav_dir)) + "%";
    let primary = sqlx::query_as::<_, LocalArtifactRow>(
        "SELECT id, storage_key, content_type, size_bytes, quarantine_status, quarantine_until \
         FROM artifacts \
         WHERE repository_id = $1 \
           AND path LIKE $2 ESCAPE '\\' \
           AND is_deleted = false \
         ORDER BY \
           CASE WHEN path LIKE '%.jar' ESCAPE '\\' OR path LIKE '%.aar' ESCAPE '\\' \
                     OR path LIKE '%.war' ESCAPE '\\' OR path LIKE '%.ear' ESCAPE '\\' \
                     OR path LIKE '%.zip' ESCAPE '\\' \
                THEN 0 ELSE 1 END ASC, \
           created_at DESC \
         LIMIT 1",
    )
    .bind(repo_id)
    .bind(&sibling_like)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    // Gate 3: Quarantine on the anchor row gates the whole GAV.
    check_quarantine_row(&primary)?;

    let storage = state.storage_for_repo_or_500(location)?;
    let storage_key = format!("maven/{}", artifact_path);
    let stream = storage.get_stream(&storage_key).await.map_err(|e| {
        let msg = e.to_string();
        if msg.to_ascii_lowercase().contains("not found") {
            (StatusCode::NOT_FOUND, "Artifact not found").into_response()
        } else {
            internal_error("Storage", e)
        }
    })?;
    Ok(StreamingFetchResult {
        body: stream,
        content_type: None,
        content_length: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::proxy_helpers::{
        insert_artifact, put_artifact_bytes, NewArtifact, RepoInfo,
    };
    use crate::api::handlers::test_db_helpers as db_helpers;
    use bytes::Bytes;


    #[test]
    fn test_is_maven_secondary_path_known_extensions() {
        for ext in [
            ".pom",
            ".module",
            "-sources.jar",
            "-javadoc.jar",
            "-tests.jar",
            "-test-sources.jar",
            ".sha1",
            ".sha256",
            ".sha512",
            ".md5",
            ".asc",
        ] {
            let path = format!("g/a/1.0/a-1.0{}", ext);
            assert!(
                is_maven_secondary_path(&path),
                "{} should be recognized as secondary",
                ext
            );
        }
    }

    #[test]
    fn test_is_maven_secondary_path_allows_classifier_artifacts() {
        for path in [
            "g/a/1.0/a-1.0-plain.jar",
            "g/a/1.0/a-1.0-test-fixtures.jar",
            "g/a/1.0/a-1.0-shadow.jar",
            "g/a/1.0/a-1.0-linux-x86_64.zip",
        ] {
            assert!(
                is_maven_secondary_path(path),
                "{} should be recognized as a classifier artifact",
                path
            );
        }
    }

    #[test]
    fn test_is_maven_secondary_path_primaries_rejected() {
        for primary in [".jar", ".aar", ".war", ".ear", ".zip"] {
            let path = format!("g/a/1.0/a-1.0{}", primary);
            assert!(
                !is_maven_secondary_path(&path),
                "{} must NOT be classified as secondary (primary files own their row)",
                primary
            );
        }
        assert!(!is_maven_secondary_path(""));
        assert!(!is_maven_secondary_path("/"));
    }


    #[test]
    fn test_is_maven_secondary_path_checksum_on_primary_classified_via_suffix() {
        let path = "g/a/1.0/a-1.0.jar.sha1";
        assert!(is_maven_secondary_path(path));
        let coords = MavenHandler::parse_coordinates(path).expect("parses");
        assert_eq!(coords.classifier, None, "`a-1.0.jar.sha1` is not a classifier artifact");
    }

    #[test]
    fn test_is_maven_secondary_path_rejects_empty_classifier() {
        let path = "g/a/1.0/a-1.0-.jar";
        assert!(!is_maven_secondary_path(path), "empty-classifier paths must not be treated as secondary");
    }

    #[test]
    fn test_is_maven_secondary_path_snapshot_mismatch_pin() {
        let mismatched = "g/a/1.0/a-1.0-SNAPSHOT.jar";
        let _ = is_maven_secondary_path(mismatched); // pins current behavior (treated as classifier)

        let correct = "g/a/1.0-SNAPSHOT/a-1.0-SNAPSHOT.jar";
        assert!(!is_maven_secondary_path(correct), "well-formed SNAPSHOT path must not be mistaken for a classifier");
    }

    #[test]
    fn test_is_maven_secondary_path_hyphenated_artifact_id_with_tests_classifier() {
        let path =
            "org/springframework/boot/spring-boot-starter/3.0/spring-boot-starter-3.0-tests.jar";
        assert!(
            is_maven_secondary_path(path),
            "classifier `tests` on a hyphenated artifact-id must be recognized"
        );
        let coords = MavenHandler::parse_coordinates(path).expect("parses");
        assert_eq!(coords.artifact_id, "spring-boot-starter");
        assert_eq!(coords.version, "3.0");
        assert_eq!(coords.classifier.as_deref(), Some("tests"));
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_is_maven_secondary_path_invalid_paths() {
        for path in [
            "just-a-file.jar",        // no directory at all
            "g/a-1.0-classifier.jar", // only 2 segments (no version dir)
            "g/a/a-1.0-x.jar",        // 3 segments, missing version dir
        ] {
            assert!(
                !is_maven_secondary_path(path),
                "{} is not a valid Maven coordinate and must not be classified as secondary",
                path
            );
        }
    }

    #[test]
    fn test_maven_gav_directory_extraction() {
        assert_eq!(maven_gav_directory("com/example/foo/1.0/foo-1.0.pom"), Some("com/example/foo/1.0"));
        assert_eq!(maven_gav_directory("nopath"), None);
        assert_eq!(maven_gav_directory("/foo.pom"), Some(""));
    }

    // ── DB-backed integration tests (no_op without DATABASE_URL) ───

    /// Fresh local-maven repo fixture.
    async fn maven_fixture() -> Option<(sqlx::PgPool, crate::api::SharedState, Uuid, RepoInfo, Uuid)>
    {
        let pool = db_helpers::try_pool().await?;
        let (user_id, _username) = db_helpers::create_user(&pool).await;
        let (repo_id, _, storage_dir) = db_helpers::create_repo(&pool, "local", "maven").await;
        let state = db_helpers::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let repo = RepoInfo {
            id: repo_id,
            key: "irrelevant".to_string(),
            storage_path: storage_dir.to_string_lossy().into_owned(),
            storage_backend: "filesystem".to_string(),
            repo_type: "local".to_string(),
            upstream_url: None,
        };
        Some((pool, state, repo_id, repo, user_id))
    }

    async fn insert_primary_jar(
        pool: &sqlx::PgPool,
        repo_id: Uuid,
        user_id: Uuid,
        path: &str,
        storage_key: &str,
    ) -> Uuid {
        insert_artifact(
            pool,
            NewArtifact {
                repository_id: repo_id,
                path,
                name: "foo",
                version: "1.0",
                size_bytes: 100,
                checksum_sha256: "primary-sha",
                content_type: "application/java-archive",
                storage_key,
                uploaded_by: user_id,
            },
        )
        .await
        .expect("insert primary")
    }

    #[tokio::test]
    async fn test_storage_fallback_hit_with_live_primary() {
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let _primary = insert_primary_jar(
            &pool,
            repo_id,
            user_id,
            "com/example/foo/1.0/foo-1.0.jar",
            "maven/com/example/foo/1.0/foo-1.0.jar",
        )
        .await;
        let bytes = Bytes::from_static(b"<project>pom-bytes</project>");
        put_artifact_bytes(
            &state,
            &repo,
            "maven/com/example/foo/1.0/foo-1.0.pom",
            bytes.clone(),
        )
        .await
        .expect("put");

        let location = repo.storage_location();
        let result = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/foo/1.0/foo-1.0.pom",
        )
        .await
        .expect("fetch");
        assert!(
            result.content_type.is_none(),
            "helper returns None for content-type"
        );
        let content = result.collect().await.unwrap();
        assert_eq!(&content[..], &bytes[..]);

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_serves_each_secondary_extension() {
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let _primary = insert_primary_jar(
            &pool,
            repo_id,
            user_id,
            "com/example/foo/1.0/foo-1.0.jar",
            "maven/com/example/foo/1.0/foo-1.0.jar",
        )
        .await;
        let location = repo.storage_location();

        for (suffix, payload) in [
            (".pom", b"<project/>".to_vec()),
            (".module", b"{\"name\":\"foo\"}".to_vec()),
            ("-sources.jar", b"sources-jar-bytes".to_vec()),
            ("-javadoc.jar", b"javadoc-jar-bytes".to_vec()),
            ("-plain.jar", b"plain-jar-bytes".to_vec()),
            ("-test-fixtures.jar", b"test-fixtures-jar-bytes".to_vec()),
            ("-shadow.jar", b"shadow-jar-bytes".to_vec()),
            (".sha512", b"a".repeat(128)),
            (".sha256", b"b".repeat(64)),
            (".sha1", b"c".repeat(40)),
            (".md5", b"d".repeat(32)),
            (".asc", b"-----BEGIN PGP SIGNATURE-----\n".to_vec()),
        ] {
            let path = format!("com/example/foo/1.0/foo-1.0{}", suffix);
            put_artifact_bytes(
                &state,
                &repo,
                &format!("maven/{}", path),
                Bytes::from(payload.clone()),
            )
            .await
            .expect("put");
            let result =
                maven_local_fetch_storage_fallback(&pool, &state, repo_id, &location, &path)
                    .await
                    .unwrap_or_else(|_| panic!("must serve secondary extension {}", suffix));
            let content = result.collect().await.unwrap();
            assert_eq!(
                &content[..],
                &payload[..],
                "round-trip mismatch for {}",
                suffix
            );
        }

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_refuses_primary_without_sibling_anchor() {
        // Primaries with no live sibling row in the same GAV directory must return 404.
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let location = repo.storage_location();

        for primary_ext in [".jar", ".aar", ".war", ".ear", ".zip"] {
            let path = format!("com/example/foo/1.0/foo-1.0{}", primary_ext);
            put_artifact_bytes(
                &state,
                &repo,
                &format!("maven/{}", path),
                Bytes::from_static(b"primary-bytes-must-not-leak"),
            )
            .await
            .expect("put");
            let err = maven_local_fetch_storage_fallback(&pool, &state, repo_id, &location, &path)
                .await
                .expect_err(&format!("primary {} with no sibling must be refused", primary_ext));
            assert_eq!(err.status(), StatusCode::NOT_FOUND);
        }

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_serves_primary_jar_anchored_by_pom_row() {
        // Primary JAR with no own DB row is served when a live sibling POM row anchors the GAV.
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        // Insert POM row (the canonical AK row for this GAV).
        let pom_path = "com/example/anc/1.0/anc-1.0.pom";
        insert_primary_jar(&pool, repo_id, user_id, pom_path, &format!("maven/{}", pom_path)).await;
        // Put primary JAR bytes with no DB row.
        let jar_path = "com/example/anc/1.0/anc-1.0.jar";
        let jar_bytes = Bytes::from_static(b"primary-jar-bytes");
        put_artifact_bytes(&state, &repo, &format!("maven/{}", jar_path), jar_bytes.clone())
            .await
            .expect("put jar");

        let location = repo.storage_location();
        let result =
            maven_local_fetch_storage_fallback(&pool, &state, repo_id, &location, jar_path)
                .await
                .expect("rowless primary anchored by sibling must be served");
        let content = result.collect().await.unwrap();
        assert_eq!(&content[..], &jar_bytes[..]);

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_refuses_deleted_primary_jar() {
        // Primary JAR with is_deleted=true own row must be refused even though a live POM sibling exists.
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        // Insert a live POM row.
        let pom_path = "com/example/del/1.0/del-1.0.pom";
        insert_primary_jar(&pool, repo_id, user_id, pom_path, &format!("maven/{}", pom_path)).await;
        // Insert soft-deleted JAR row.
        let jar_path = "com/example/del/1.0/del-1.0.jar";
        let jar_id =
            insert_primary_jar(&pool, repo_id, user_id, jar_path, &format!("maven/{}", jar_path))
                .await;
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(jar_id)
            .execute(&pool)
            .await
            .expect("soft-delete jar");
        put_artifact_bytes(
            &state,
            &repo,
            &format!("maven/{}", jar_path),
            Bytes::from_static(b"deleted-jar-must-not-leak"),
        )
        .await
        .expect("put jar bytes");

        let location = repo.storage_location();
        let err = maven_local_fetch_storage_fallback(&pool, &state, repo_id, &location, jar_path)
            .await
            .expect_err("soft-deleted primary must be refused");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_refuses_orphan_secondary() {
        // Secondary bytes with no live sibling row (orphaned) must return 404.
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let location = repo.storage_location();

        put_artifact_bytes(
            &state,
            &repo,
            "maven/com/example/orphan/1.0/orphan-1.0.pom",
            Bytes::from_static(b"<project>orphan</project>"),
        )
        .await
        .expect("put");

        let err = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/orphan/1.0/orphan-1.0.pom",
        )
        .await
        .expect_err("orphan secondary must be refused");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_honors_quarantine_on_primary() {
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let primary_id = insert_primary_jar(
            &pool,
            repo_id,
            user_id,
            "com/example/qfoo/1.0/qfoo-1.0.jar",
            "maven/com/example/qfoo/1.0/qfoo-1.0.jar",
        )
        .await;
        sqlx::query(
            "UPDATE artifacts SET quarantine_status = 'quarantined', \
             quarantine_until = NULL WHERE id = $1",
        )
        .bind(primary_id)
        .execute(&pool)
        .await
        .expect("set quarantine");

        put_artifact_bytes(
            &state,
            &repo,
            "maven/com/example/qfoo/1.0/qfoo-1.0.pom",
            Bytes::from_static(b"<project>qfoo</project>"),
        )
        .await
        .expect("put");

        let location = repo.storage_location();
        let err = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/qfoo/1.0/qfoo-1.0.pom",
        )
        .await
        .expect_err("quarantined primary must hold back its companions");
        assert!(
            err.status() == StatusCode::CONFLICT
                || err.status() == StatusCode::FORBIDDEN
                || err.status() == StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
                || err.status() == StatusCode::NOT_FOUND,
            "expected a refusal status, got {}",
            err.status()
        );

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_honors_quarantine_on_classifier_artifact() {
        // Quarantined primary must also gate classifier siblings (e.g. `-plain.jar`).
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let primary_id = insert_primary_jar(
            &pool,
            repo_id,
            user_id,
            "com/example/cfoo/1.0/cfoo-1.0.jar",
            "maven/com/example/cfoo/1.0/cfoo-1.0.jar",
        )
        .await;
        sqlx::query(
            "UPDATE artifacts SET quarantine_status = 'quarantined', \
             quarantine_until = NULL WHERE id = $1",
        )
        .bind(primary_id)
        .execute(&pool)
        .await
        .expect("set quarantine");

        // Drop classifier bytes onto storage as if a publish had landed
        // them alongside the primary. Without quarantine these would be
        // served by Gate 3.
        put_artifact_bytes(
            &state,
            &repo,
            "maven/com/example/cfoo/1.0/cfoo-1.0-plain.jar",
            Bytes::from_static(b"plain-classifier-bytes-must-not-leak"),
        )
        .await
        .expect("put classifier");

        let location = repo.storage_location();
        let err = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/cfoo/1.0/cfoo-1.0-plain.jar",
        )
        .await
        .expect_err("quarantined primary must hold back its classifier siblings");
        assert!(
            err.status() == StatusCode::CONFLICT
                || err.status() == StatusCode::FORBIDDEN
                || err.status() == StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
                || err.status() == StatusCode::NOT_FOUND,
            "expected a refusal status, got {}",
            err.status()
        );

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_honors_soft_delete_on_primary() {
        // Soft-deleted primary anchor means the GAV is retracted; companions must return 404.
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let primary_id = insert_primary_jar(
            &pool,
            repo_id,
            user_id,
            "com/example/dfoo/1.0/dfoo-1.0.jar",
            "maven/com/example/dfoo/1.0/dfoo-1.0.jar",
        )
        .await;
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(primary_id)
            .execute(&pool)
            .await
            .expect("soft-delete");

        put_artifact_bytes(
            &state,
            &repo,
            "maven/com/example/dfoo/1.0/dfoo-1.0.pom",
            Bytes::from_static(b"<project>dfoo</project>"),
        )
        .await
        .expect("put");

        let location = repo.storage_location();
        let err = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/dfoo/1.0/dfoo-1.0.pom",
        )
        .await
        .expect_err("soft-deleted primary must hold back its companions");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_storage_fallback_isolates_maven_prefix() {
        // Bytes under pypi/ must not satisfy a maven fallback query.
        let Some((pool, state, repo_id, repo, user_id)) = maven_fixture().await else {
            return;
        };
        let location = repo.storage_location();

        let _primary = insert_primary_jar(
            &pool,
            repo_id,
            user_id,
            "com/example/iso/1.0/iso-1.0.jar",
            "maven/com/example/iso/1.0/iso-1.0.jar",
        )
        .await;
        put_artifact_bytes(
            &state,
            &repo,
            "maven/com/example/iso/1.0/iso-1.0.pom",
            Bytes::from_static(b"maven-pom"),
        )
        .await
        .expect("put maven");
        let result = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/iso/1.0/iso-1.0.pom",
        )
        .await
        .expect("positive: maven/<path> with live primary serves");
        let got = result.collect().await.unwrap();
        assert_eq!(&got[..], b"maven-pom");

        put_artifact_bytes(
            &state,
            &repo,
            "pypi/com/example/leak/1.0/leak-1.0.pom",
            Bytes::from_static(b"pypi-bytes-must-not-leak"),
        )
        .await
        .expect("put pypi");
        let err = maven_local_fetch_storage_fallback(
            &pool,
            &state,
            repo_id,
            &location,
            "com/example/leak/1.0/leak-1.0.pom",
        )
        .await
        .expect_err("pypi-prefixed bytes must not satisfy a maven fallback");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }
}
