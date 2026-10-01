#![allow(clippy::needless_return)]

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};
use tauri::{AppHandle, Emitter, Manager};
use walkdir::WalkDir;

static SCAN_CANCELLED: AtomicBool = AtomicBool::new(false);

const APP_VERSION: &str = "0.3.6";
const UPDATE_MANIFEST_URL: &str =
    "https://github.com/gvrsim99-sudo/PC-Cleaner/releases/latest/download/latest.json";
const RELEASE_PAGE_URL: &str = "https://github.com/gvrsim99-sudo/PC-Cleaner/releases/latest";
const MAX_ITEMS: usize = 5000;
const MAX_DUPLICATE_FILES: usize = 50_000;
const MIN_DUPLICATE_SIZE: u64 = 8 * 1024;
const STORAGE_FILE_LIMIT: usize = 750_000;
const SMART_TASK_NAME: &str = "PC Cleaner Smart Clean";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupItem {
    pub id: String,
    pub path: String,
    pub name: String,
    pub category: String,
    pub reason: String,
    pub size: u64,
    pub safe_to_delete: bool,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DuplicateFile {
    pub path: String,
    pub size: u64,
    pub modified_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DuplicateGroup {
    pub hash: String,
    pub size: u64,
    pub files: Vec<DuplicateFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageEntry {
    pub path: String,
    pub size: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DriveInfo {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub used_bytes: u64,
    pub used_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanSummary {
    pub total_bytes: u64,
    pub total_items: usize,
    pub by_category: BTreeMap<String, u64>,
    pub items: Vec<CleanupItem>,
    pub duplicates: Vec<DuplicateGroup>,
    pub largest_files: Vec<StorageEntry>,
    pub scanned_roots: Vec<String>,
    pub warnings: Vec<String>,
    pub drive: DriveInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CleanupReport {
    pub deleted_items: usize,
    pub deleted_bytes: u64,
    pub failed_items: usize,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub name: String,
    pub size: u64,
    pub moved_unix: u64,
}

fn quarantine_root() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir())
        .join("PC Cleaner")
        .join("Quarantine")
}

fn quarantine_manifest() -> PathBuf {
    quarantine_root().join("manifest.json")
}

fn app_data_root() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
        .join("PC Cleaner")
}

fn settings_path() -> PathBuf {
    app_data_root().join("settings.json")
}

fn read_settings() -> CleanerSettings {
    let mut settings: CleanerSettings = fs::read(settings_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    if settings.update_manifest_url.trim().is_empty()
        || settings
            .update_manifest_url
            .contains("DefenderGuard/pc-cleaner-updates")
    {
        settings.update_manifest_url = UPDATE_MANIFEST_URL.into();
    }
    if settings.release_page_url.trim().is_empty()
        || settings.release_page_url.contains("DefenderGuard")
    {
        settings.release_page_url = RELEASE_PAGE_URL.into();
    }
    settings
}

fn write_settings(settings: &CleanerSettings) -> Result<(), String> {
    let root = app_data_root();
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?;
    fs::write(settings_path(), bytes).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActionLogEntry {
    pub action: String,
    pub item: String,
    pub size: u64,
    pub timestamp_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CleanerSettings {
    pub scan_user_temp: bool,
    pub scan_system_temp: bool,
    pub scan_browser_cache: bool,
    pub scan_windows_update: bool,
    pub scan_crash_dumps: bool,
    pub scan_shader_cache: bool,
    pub scan_recycle_bin: bool,
    pub scan_large_files: bool,
    pub scan_duplicates: bool,
    pub scan_thumbnails: bool,
    pub scan_app_caches: bool,
    pub scan_old_installers: bool,
    pub recent_protection_hours: u64,
    pub excluded_paths: Vec<String>,
    pub cleanup_allowed_categories: Vec<String>,
    pub quarantine_max_gb: u64,
    pub quarantine_retention_days: u64,
    pub auto_start: bool,
    pub minimize_to_tray: bool,
    pub smart_clean_enabled: bool,
    pub smart_clean_time: String,
    pub smart_clean_days: Vec<String>,
    pub smart_clean_include_duplicates: bool,
    pub smart_clean_max_gb: u64,
    pub update_manifest_url: String,
    pub release_page_url: String,
}

impl Default for CleanerSettings {
    fn default() -> Self {
        Self {
            scan_user_temp: true,
            scan_system_temp: true,
            scan_browser_cache: true,
            scan_windows_update: false,
            scan_crash_dumps: true,
            scan_shader_cache: true,
            scan_recycle_bin: true,
            scan_large_files: true,
            scan_duplicates: true,
            scan_thumbnails: true,
            scan_app_caches: true,
            scan_old_installers: true,
            recent_protection_hours: 24,
            excluded_paths: Vec::new(),
            cleanup_allowed_categories: vec![
                "Временные файлы".into(),
                "Системные временные файлы".into(),
                "Кэш браузера".into(),
                "Дампы сбоев".into(),
                "Отчёты сбоев Windows".into(),
                "Графический кэш".into(),
                "Кэш приложений".into(),
                "Кэш миниатюр".into(),
                "Дубликаты".into(),
            ],
            quarantine_max_gb: 10,
            quarantine_retention_days: 30,
            auto_start: false,
            minimize_to_tray: true,
            smart_clean_enabled: false,
            smart_clean_time: "03:00".into(),
            smart_clean_days: vec!["SUN".into()],
            smart_clean_include_duplicates: false,
            smart_clean_max_gb: 5,
            update_manifest_url: UPDATE_MANIFEST_URL.into(),
            release_page_url: RELEASE_PAGE_URL.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanProgress {
    pub stage: String,
    pub detail: String,
    pub current: u64,
    pub total: u64,
    pub percent: f64,
    pub found_bytes: u64,
    pub found_items: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageBucket {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub file_count: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrowserCacheInfo {
    pub browser: String,
    pub path: String,
    pub size: u64,
    pub file_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrowserDataInfo {
    pub browser: String,
    pub category: String,
    pub path: String,
    pub size: u64,
    pub file_count: u64,
    pub risky: bool,
}

fn action_log_path() -> PathBuf {
    quarantine_root().join("activity.json")
}

fn read_action_log() -> Vec<ActionLogEntry> {
    fs::read(action_log_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn append_action(action: &str, item: &str, size: u64) -> Result<(), String> {
    let mut log = read_action_log();
    log.push(ActionLogEntry {
        action: action.to_string(),
        item: item.to_string(),
        size,
        timestamp_unix: unix_now(),
    });
    if log.len() > 500 {
        let keep_from = log.len() - 500;
        log = log.split_off(keep_from);
    }
    let root = quarantine_root();
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(&log).map_err(|e| e.to_string())?;
    fs::write(action_log_path(), bytes).map_err(|e| e.to_string())
}

fn read_quarantine_manifest() -> Vec<QuarantineItem> {
    fs::read(quarantine_manifest())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_quarantine_manifest(items: &[QuarantineItem]) -> Result<(), String> {
    let root = quarantine_root();
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(items).map_err(|e| e.to_string())?;
    fs::write(quarantine_manifest(), bytes).map_err(|e| e.to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now() -> SystemTime {
    SystemTime::now()
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn is_excluded(path: &Path, settings: &CleanerSettings) -> bool {
    let candidate = normalize_path(path);
    settings.excluded_paths.iter().any(|excluded| {
        let value = excluded.trim().replace('/', "\\").to_ascii_lowercase();
        !value.is_empty() && (candidate == value || candidate.starts_with(&(value + "\\")))
    })
}

fn is_recent_with_settings(meta: &fs::Metadata, settings: &CleanerSettings) -> bool {
    let protection = Duration::from_secs(settings.recent_protection_hours.max(1) * 60 * 60);
    match meta.modified() {
        Ok(modified) => now().duration_since(modified).unwrap_or_default() < protection,
        Err(_) => false,
    }
}

fn cleanup_category_allowed(category: &str, settings: &CleanerSettings) -> bool {
    settings
        .cleanup_allowed_categories
        .iter()
        .any(|value| value.eq_ignore_ascii_case(category))
}

fn is_protected_duplicate_path(path: &Path) -> bool {
    let p = normalize_path(path);
    let protected = [
        "\\windows\\",
        "\\program files\\",
        "\\program files (x86)\\",
        "\\programdata\\",
        "\\users\\public\\",
        "\\documents\\",
        "\\desktop\\",
        "\\onedrive\\",
        "\\projects\\",
        "\\repos\\",
        "\\repo\\",
        "\\work\\",
    ];
    protected.iter().any(|root| p.contains(root))
}

fn purge_expired_quarantine(settings: &CleanerSettings) -> Result<(usize, u64), String> {
    let mut manifest = read_quarantine_manifest();
    if manifest.is_empty() {
        return Ok((0, 0));
    }
    let cutoff =
        unix_now().saturating_sub(settings.quarantine_retention_days.max(1) * 24 * 60 * 60);
    let mut remaining = Vec::with_capacity(manifest.len());
    let mut purged = 0usize;
    let mut purged_bytes = 0u64;
    for item in manifest.drain(..) {
        if item.moved_unix <= cutoff {
            let path = PathBuf::from(&item.quarantine_path);
            match fs::remove_file(&path) {
                Ok(_) => {
                    purged += 1;
                    purged_bytes = purged_bytes.saturating_add(item.size);
                    let _ = append_action("Автоудаление карантина", &item.original_path, item.size);
                }
                Err(_) if !path.exists() => {}
                Err(_) => remaining.push(item),
            }
        } else {
            remaining.push(item);
        }
    }
    write_quarantine_manifest(&remaining)?;
    Ok((purged, purged_bytes))
}

fn emit_progress(
    app: &AppHandle,
    stage: &str,
    detail: &str,
    current: u64,
    total: u64,
    found_bytes: u64,
    found_items: usize,
) {
    let percent = if total == 0 {
        -1.0
    } else {
        ((current as f64 / total as f64) * 100.0).clamp(0.0, 100.0)
    };
    let _ = app.emit(
        "scan-progress",
        ScanProgress {
            stage: stage.to_string(),
            detail: detail.to_string(),
            current,
            total,
            percent,
            found_bytes,
            found_items,
        },
    );
}

fn path_from_env(key: &str) -> Option<PathBuf> {
    env::var_os(key).map(PathBuf::from).filter(|p| p.exists())
}

fn analysis_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    if let Some(home) = path_from_env("USERPROFILE") {
        for child in ["Downloads", "Desktop", "Documents", "Pictures", "Videos"] {
            let p = home.join(child);
            if p.exists() && seen.insert(normalize_path(&p)) {
                roots.push(p);
            }
        }
    }
    roots
}

#[cfg(windows)]
fn current_drive_info() -> DriveInfo {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let root: Vec<u16> = std::ffi::OsStr::new(r#"C:\"#)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut free = 0u64;
    let mut total = 0u64;
    let mut total_free = 0u64;
    let ok = unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut free, &mut total, &mut total_free) };
    if ok == 0 || total == 0 {
        return DriveInfo::default();
    }
    let used = total.saturating_sub(free);
    DriveInfo {
        total_bytes: total,
        free_bytes: free,
        used_bytes: used,
        used_percent: (used as f64 / total as f64) * 100.0,
    }
}

#[cfg(not(windows))]
fn current_drive_info() -> DriveInfo {
    DriveInfo::default()
}

fn add_item(summary: &mut ScanSummary, item: CleanupItem) {
    summary.total_bytes = summary.total_bytes.saturating_add(item.size);
    summary.total_items += 1;
    *summary
        .by_category
        .entry(item.category.clone())
        .or_default() += item.size;
    if summary.items.len() < MAX_ITEMS {
        summary.items.push(item);
    }
}

fn hash_file(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(hasher.finalize().to_hex().to_string())
}

fn file_modified_unix(meta: &fs::Metadata) -> Option<u64> {
    let modified = meta.modified().ok()?;
    let duration = modified.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    Some(duration.as_secs())
}

fn configured_junk_roots(
    settings: &CleanerSettings,
) -> Vec<(PathBuf, &'static str, bool, &'static str)> {
    let mut roots = Vec::new();
    if let Some(p) = path_from_env("TEMP") {
        if settings.scan_user_temp {
            roots.push((
                p,
                "Временные файлы",
                true,
                "Временные данные текущего пользователя",
            ));
        }
    }
    if let Some(local) = path_from_env("LOCALAPPDATA") {
        if settings.scan_user_temp {
            let p = local.join("Temp");
            if p.exists() {
                roots.push((p, "Временные файлы", true, "Локальный каталог Temp"));
            }
        }
        if settings.scan_browser_cache {
            let browsers = [
                (
                    "Google Chrome",
                    local.join("Google/Chrome/User Data/Default/Cache"),
                ),
                (
                    "Microsoft Edge",
                    local.join("Microsoft/Edge/User Data/Default/Cache"),
                ),
            ];
            for (name, p) in browsers {
                if p.exists() {
                    roots.push((
                        p,
                        "Кэш браузера",
                        true,
                        if name == "Google Chrome" {
                            "Кэш Google Chrome"
                        } else {
                            "Кэш Microsoft Edge"
                        },
                    ));
                }
            }
            let firefox = local.join("Mozilla/Firefox/Profiles");
            if firefox.exists() {
                for entry in WalkDir::new(&firefox)
                    .max_depth(2)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(Result::ok)
                {
                    if entry.file_type().is_dir() && entry.file_name() == "cache2" {
                        roots.push((
                            entry.path().to_path_buf(),
                            "Кэш браузера",
                            false,
                            "Кэш Firefox помечен для проверки перед очисткой",
                        ));
                    }
                }
            }
        }
        if settings.scan_crash_dumps {
            for p in [local.join("CrashDumps")] {
                if p.exists() {
                    roots.push((
                        p,
                        "Дампы сбоев",
                        true,
                        "Локальные диагностические дампы приложений",
                    ));
                }
            }
        }
        if settings.scan_shader_cache {
            for p in [
                local.join("D3DSCache"),
                local.join("NVIDIA/DXCache"),
                local.join("NVIDIA/GLCache"),
                local.join("AMD/DxCache"),
            ] {
                if p.exists() {
                    roots.push((
                        p,
                        "Графический кэш",
                        true,
                        "Кэш шейдеров; при необходимости будет создан заново",
                    ));
                }
            }
        }
        if settings.scan_thumbnails {
            let explorer = local.join("Microsoft/Windows/Explorer");
            if explorer.exists() {
                if let Ok(entries) = fs::read_dir(&explorer) {
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                        if path.is_file() && name.starts_with("thumbcache") && name.ends_with(".db")
                        {
                            roots.push((
                                path,
                                "Кэш миниатюр",
                                true,
                                "Кэш миниатюр Windows; файл будет создан заново при необходимости",
                            ));
                        }
                    }
                }
            }
        }
        if settings.scan_app_caches {
            let appdata = path_from_env("APPDATA");
            let candidates = [
                ("Discord/Cache", "Discord"),
                ("Discord/Code Cache", "Discord"),
                ("Slack/Cache", "Slack"),
                ("Slack/Code Cache", "Slack"),
            ];
            if let Some(appdata) = appdata {
                for (relative, name) in candidates {
                    let p = appdata.join(relative);
                    if p.exists() {
                        roots.push((
                            p,
                            "Кэш приложений",
                            true,
                            if name == "Discord" {
                                "Кэш Discord"
                            } else {
                                "Кэш Slack"
                            },
                        ));
                    }
                }
            }
            for (relative, name) in [
                ("Microsoft/Teams/Cache", "Microsoft Teams"),
                ("Microsoft/Teams/Code Cache", "Microsoft Teams"),
            ] {
                let p = local.join(relative);
                if p.exists() {
                    roots.push((
                        p,
                        "Кэш приложений",
                        true,
                        if name == "Microsoft Teams" {
                            "Кэш Microsoft Teams"
                        } else {
                            "Кэш приложения"
                        },
                    ));
                }
            }
        }
    }
    if settings.scan_system_temp {
        if let Some(windir) = path_from_env("WINDIR") {
            let p = windir.join("Temp");
            if p.exists() {
                roots.push((
                    p,
                    "Системные временные файлы",
                    true,
                    "Системный каталог Temp; занятые файлы пропускаются",
                ));
            }
        }
    }
    if settings.scan_crash_dumps {
        if let Some(program_data) = path_from_env("PROGRAMDATA") {
            for p in [
                program_data.join("Microsoft/Windows/WER/ReportQueue"),
                program_data.join("Microsoft/Windows/WER/ReportArchive"),
            ] {
                if p.exists() {
                    roots.push((
                        p,
                        "Отчёты сбоев Windows",
                        true,
                        "Диагностические отчёты Windows Error Reporting",
                    ));
                }
            }
        }
    }
    if settings.scan_windows_update {
        if let Some(windir) = path_from_env("WINDIR") {
            for p in [
                windir.join("SoftwareDistribution/Download"),
                windir.join("SoftwareDistribution/DeliveryOptimization"),
            ] {
                if p.exists() {
                    roots.push((
                        p,
                        "Кэш обновлений Windows",
                        false,
                        "Каталог обновлений Windows; требуется дополнительная проверка",
                    ));
                }
            }
        }
    }
    let mut unique = Vec::with_capacity(roots.len());
    let mut seen = HashSet::new();
    for root in roots {
        let key = normalize_path(&root.0);
        if seen.insert(key) {
            unique.push(root);
        }
    }
    unique
}

fn collect_old_installers(app: &AppHandle, summary: &mut ScanSummary, settings: &CleanerSettings) {
    if !settings.scan_old_installers {
        return;
    }
    let Some(home) = path_from_env("USERPROFILE") else {
        return;
    };
    let downloads = home.join("Downloads");
    if !downloads.is_dir() {
        return;
    }
    let installer_ext = ["exe", "msi", "msp", "iso", "img"];
    let cutoff = unix_now().saturating_sub(90 * 24 * 60 * 60);
    let mut checked = 0u64;
    for entry in WalkDir::new(&downloads)
        .follow_links(false)
        .max_depth(4)
        .into_iter()
        .filter_map(Result::ok)
    {
        if SCAN_CANCELLED.load(Ordering::Relaxed) {
            return;
        }
        let path = entry.path();
        if !entry.file_type().is_file() || is_excluded(path, settings) {
            continue;
        }
        checked += 1;
        let Ok(meta) = entry.metadata() else { continue };
        if meta.len() < 10 * 1024 * 1024 || is_recent_with_settings(&meta, settings) {
            continue;
        }
        let modified = file_modified_unix(&meta).unwrap_or_else(unix_now);
        let ext = path
            .extension()
            .and_then(|x| x.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if modified <= cutoff && installer_ext.contains(&ext.as_str()) {
            add_item(summary, CleanupItem {
                id: blake3::hash(path.to_string_lossy().as_bytes()).to_hex().to_string(),
                path: path.display().to_string(),
                name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
                category: "Старые установочные файлы".into(),
                reason: "Установочный образ или пакет в Downloads старше 90 дней; проверьте перед удалением".into(),
                size: meta.len(),
                safe_to_delete: false,
                confidence: "требует проверки".into(),
            });
        }
        if checked % 250 == 0 {
            emit_progress(
                app,
                "Установочные файлы",
                &format!("Проверено {} файлов в Downloads", checked),
                0,
                0,
                summary.total_bytes,
                summary.total_items,
            );
        }
    }
}

fn scan_configured_junk(app: &AppHandle, summary: &mut ScanSummary, settings: &CleanerSettings) {
    let roots = configured_junk_roots(settings);
    for (root, category, safe, reason) in roots.into_iter() {
        if SCAN_CANCELLED.load(Ordering::Relaxed) {
            break;
        }
        let mut current = 0u64;
        let mut found = 0u64;
        for entry in WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if SCAN_CANCELLED.load(Ordering::Relaxed) {
                break;
            }
            let path = entry.path();
            if !entry.file_type().is_file() || is_excluded(path, settings) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            current += 1;
            if is_recent_with_settings(&meta, settings) || meta.len() == 0 {
                continue;
            }
            let size = meta.len();
            let id = blake3::hash(path.to_string_lossy().as_bytes())
                .to_hex()
                .to_string();
            add_item(
                summary,
                CleanupItem {
                    id,
                    path: path.display().to_string(),
                    name: path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    category: category.to_string(),
                    reason: reason.to_string(),
                    size,
                    safe_to_delete: safe,
                    confidence: if safe {
                        "высокая"
                    } else {
                        "требует проверки"
                    }
                    .to_string(),
                },
            );
            found += 1;
            if current % 250 == 0 {
                let stage = if category == "Кэш браузера" {
                    "Браузеры"
                } else {
                    "Временные файлы"
                };
                emit_progress(
                    app,
                    stage,
                    &format!("{} · проверено {} файлов", category, current),
                    current,
                    0,
                    summary.total_bytes,
                    summary.total_items,
                );
            }
        }
        summary.scanned_roots.push(root.display().to_string());
        let stage = if category == "Кэш браузера" {
            "Браузеры"
        } else {
            "Временные файлы"
        };
        emit_progress(
            app,
            stage,
            &format!("{} завершено · найдено {}", category, found),
            current,
            0,
            summary.total_bytes,
            summary.total_items,
        );
    }
}

fn collect_largest_configured(
    app: &AppHandle,
    summary: &mut ScanSummary,
    settings: &CleanerSettings,
) {
    if !settings.scan_large_files {
        return;
    }
    let roots = analysis_roots();
    let mut files = Vec::new();
    let mut current = 0u64;
    for root in roots {
        for entry in WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if SCAN_CANCELLED.load(Ordering::Relaxed) {
                return;
            }
            let path = entry.path();
            if !entry.file_type().is_file() || is_excluded(path, settings) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            current += 1;
            if meta.len() >= 50 * 1024 * 1024 {
                files.push(StorageEntry {
                    path: path.display().to_string(),
                    size: meta.len(),
                    kind: "file".into(),
                });
            }
            if current % 500 == 0 {
                emit_progress(
                    app,
                    "Крупные файлы",
                    &format!("Проверено {} файлов", current),
                    0,
                    0,
                    summary.total_bytes,
                    summary.total_items,
                );
            }
        }
    }
    files.sort_by(|a, b| b.size.cmp(&a.size));
    files.truncate(50);
    summary.largest_files = files;
}

fn scan_duplicates_configured(
    app: &AppHandle,
    summary: &mut ScanSummary,
    settings: &CleanerSettings,
) {
    if !settings.scan_duplicates {
        return;
    }
    let mut by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    let mut count = 0usize;
    for root in analysis_roots() {
        for entry in WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if SCAN_CANCELLED.load(Ordering::Relaxed) {
                return;
            }
            let path = entry.path();
            if !entry.file_type().is_file() || is_excluded(path, settings) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() < MIN_DUPLICATE_SIZE || is_recent_with_settings(&meta, settings) {
                continue;
            }
            count += 1;
            by_size
                .entry(meta.len())
                .or_default()
                .push(path.to_path_buf());
            if count >= MAX_DUPLICATE_FILES {
                summary.warnings.push(format!(
                    "Поиск дубликатов ограничен {} файлами.",
                    MAX_DUPLICATE_FILES
                ));
                break;
            }
        }
        if count >= MAX_DUPLICATE_FILES {
            break;
        }
    }
    let total_candidates = count.max(1) as u64;
    let mut hashed = 0u64;
    let mut groups = Vec::new();
    for (size, paths) in by_size.into_iter().filter(|(_, p)| p.len() > 1) {
        let mut by_hash: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for path in paths {
            if let Some(hash) = hash_file(&path) {
                by_hash.entry(hash).or_default().push(path);
            }
            hashed += 1;
            if hashed % 50 == 0 {
                emit_progress(
                    app,
                    "Дубликаты",
                    &format!("Хеширование {} из {} файлов", hashed, total_candidates),
                    hashed,
                    total_candidates,
                    summary.total_bytes,
                    summary.total_items,
                );
            }
        }
        for (hash, same) in by_hash.into_iter().filter(|(_, p)| p.len() > 1) {
            let files = same
                .into_iter()
                .filter_map(|path| {
                    let meta = fs::metadata(&path).ok()?;
                    Some(DuplicateFile {
                        path: path.display().to_string(),
                        size,
                        modified_unix: file_modified_unix(&meta),
                    })
                })
                .collect::<Vec<_>>();
            if files.len() > 1 {
                groups.push(DuplicateGroup { hash, size, files });
            }
        }
    }
    groups.sort_by(|a, b| {
        let a_saved = a
            .size
            .saturating_mul(a.files.len().saturating_sub(1) as u64);
        let b_saved = b
            .size
            .saturating_mul(b.files.len().saturating_sub(1) as u64);
        b_saved.cmp(&a_saved)
    });
    groups.truncate(300);
    summary.duplicates = groups;
    emit_progress(
        app,
        "Дубликаты",
        "Поиск дубликатов завершён",
        total_candidates,
        total_candidates,
        summary.total_bytes,
        summary.total_items,
    );
}

#[cfg(windows)]
fn recycle_bin_info() -> Option<(u64, u64)> {
    #[repr(C)]
    struct ShQueryRbInfo {
        cb_size: u32,
        i64_size: i64,
        i64_num_items: i64,
    }
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHQueryRecycleBinW(root: *const u16, info: *mut ShQueryRbInfo) -> i32;
    }
    let root: Vec<u16> = std::ffi::OsStr::new(r#"C:\"#)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut info = ShQueryRbInfo {
        cb_size: std::mem::size_of::<ShQueryRbInfo>() as u32,
        i64_size: 0,
        i64_num_items: 0,
    };
    let hr = unsafe { SHQueryRecycleBinW(root.as_ptr(), &mut info) };
    if hr == 0 {
        Some((
            info.i64_size.max(0) as u64,
            info.i64_num_items.max(0) as u64,
        ))
    } else {
        None
    }
}

#[cfg(not(windows))]
fn recycle_bin_info() -> Option<(u64, u64)> {
    None
}

fn scan_recycle_bin(summary: &mut ScanSummary, settings: &CleanerSettings) {
    if !settings.scan_recycle_bin {
        return;
    }
    if let Some((size, count)) = recycle_bin_info() {
        if size > 0 {
            summary.total_bytes = summary.total_bytes.saturating_add(size);
            summary.total_items += count as usize;
            *summary.by_category.entry("Корзина".into()).or_default() += size;
        }
    }
}

fn scan_system_sync(app: &AppHandle, settings: &CleanerSettings) -> ScanSummary {
    SCAN_CANCELLED.store(false, Ordering::Relaxed);
    let mut summary = ScanSummary::default();
    summary.drive = current_drive_info();
    emit_progress(app, "Подготовка", "Запускаем анализ", 0, 0, 0, 0);
    emit_progress(
        app,
        "Временные файлы",
        "Проверяем кэши и временные каталоги",
        0,
        0,
        0,
        0,
    );
    scan_configured_junk(app, &mut summary, settings);
    scan_recycle_bin(&mut summary, settings);
    emit_progress(
        app,
        "Установочные файлы",
        "Проверяем старые установочные файлы",
        0,
        0,
        summary.total_bytes,
        summary.total_items,
    );
    collect_old_installers(app, &mut summary, settings);
    collect_largest_configured(app, &mut summary, settings);
    summary.items.sort_by(|a, b| b.size.cmp(&a.size));
    emit_progress(
        app,
        "Крупные файлы",
        "Поиск крупных файлов завершён",
        100,
        100,
        summary.total_bytes,
        summary.total_items,
    );
    emit_progress(
        app,
        "Завершено",
        "Сканирование завершено",
        100,
        100,
        summary.total_bytes,
        summary.total_items,
    );
    summary
}

#[tauri::command]
async fn scan_system(app: AppHandle) -> Result<ScanSummary, String> {
    let settings = read_settings();
    tauri::async_runtime::spawn_blocking(move || Ok(scan_system_sync(&app, &settings)))
        .await
        .map_err(|err| format!("Задача сканирования завершилась с ошибкой: {err}"))?
}

#[tauri::command]
async fn scan_duplicates_only(app: AppHandle) -> Result<Vec<DuplicateGroup>, String> {
    let settings = read_settings();
    tauri::async_runtime::spawn_blocking(move || {
        let mut summary = ScanSummary::default();
        scan_duplicates_configured(&app, &mut summary, &settings);
        Ok(summary.duplicates)
    })
    .await
    .map_err(|err| format!("Задача поиска дубликатов завершилась с ошибкой: {err}"))?
}

#[tauri::command]
fn cancel_scan() -> bool {
    SCAN_CANCELLED.store(true, Ordering::Relaxed);
    true
}

#[tauri::command]
fn get_settings() -> CleanerSettings {
    read_settings()
}

#[tauri::command]
fn save_settings(settings: CleanerSettings) -> Result<CleanerSettings, String> {
    let mut normalized = settings;
    normalized.recent_protection_hours = normalized.recent_protection_hours.clamp(1, 168);
    normalized.quarantine_max_gb = normalized.quarantine_max_gb.clamp(1, 1000);
    normalized.quarantine_retention_days = normalized.quarantine_retention_days.clamp(1, 3650);
    normalized.smart_clean_max_gb = normalized.smart_clean_max_gb.clamp(1, 100);
    normalized.excluded_paths = normalized
        .excluded_paths
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    normalized.cleanup_allowed_categories = normalized
        .cleanup_allowed_categories
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    normalized
        .smart_clean_days
        .retain(|d| ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"].contains(&d.as_str()));
    if normalized.smart_clean_days.is_empty() {
        normalized.smart_clean_days.push("SUN".into());
    }
    if normalized.update_manifest_url.trim().is_empty() {
        normalized.update_manifest_url = UPDATE_MANIFEST_URL.into();
    }
    write_settings(&normalized)?;
    Ok(normalized)
}

#[tauri::command]
fn app_version() -> String {
    APP_VERSION.to_string()
}

fn parse_version(value: &str) -> [u64; 3] {
    let clean = value.trim().trim_start_matches(['v', 'V']);
    let mut parts = [0u64; 3];
    for (index, part) in clean.split('.').take(3).enumerate() {
        parts[index] = part
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>()
            .parse::<u64>()
            .unwrap_or(0);
    }
    parts
}

fn version_is_newer(candidate: &str, current: &str) -> bool {
    parse_version(candidate) > parse_version(current)
}

fn validate_update_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("Для автоматической установки обновлений требуется HTTPS-ссылка.".into());
    }
    if url.len() > 4096 {
        return Err("Ссылка обновления слишком длинная.".into());
    }
    Ok(())
}

fn normalize_sha256(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("Манифест содержит некорректный SHA-256.".into());
    }
    Ok(normalized)
}

fn powershell_b64(value: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
}

fn run_powershell_script(script: &str) -> Result<(), String> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .map_err(|error| format!("Не удалось запустить PowerShell: {error}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        Err(format!(
            "PowerShell завершился с кодом {}.",
            output.status.code().unwrap_or(-1)
        ))
    } else {
        Err(stderr)
    }
}

fn download_update(url: &str, destination: &Path) -> Result<(), String> {
    let url_b64 = powershell_b64(url);
    let destination_b64 = powershell_b64(&destination.display().to_string());
    let script = format!(
        "$ErrorActionPreference='Stop';         $ProgressPreference='SilentlyContinue';         $url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}'));         $out=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}'));         [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;         Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out;         if (!(Test-Path -LiteralPath $out)) {{ throw 'Файл обновления не был загружен.' }}",
        url_b64, destination_b64
    );
    run_powershell_script(&script)
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let path_b64 = powershell_b64(&path.display().to_string());
    let script = format!(
        "$ErrorActionPreference='Stop';         $path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}'));         (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash",
        path_b64
    );
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()
        .map_err(|error| format!("Не удалось вычислить SHA-256: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            "Не удалось вычислить SHA-256 файла обновления.".into()
        } else {
            stderr
        });
    }

    let hash = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    normalize_sha256(&hash)
}

#[cfg(windows)]
fn launch_update_helper(target: &Path, downloaded: &Path, process_id: u32) -> Result<(), String> {
    let helper_path = env::temp_dir().join(format!("PC-Cleaner-Updater-{}.ps1", process_id));
    let target_b64 = powershell_b64(&target.display().to_string());
    let downloaded_b64 = powershell_b64(&downloaded.display().to_string());
    let helper_b64 = powershell_b64(&helper_path.display().to_string());
    let script = r#"
param(
    [Parameter(Mandatory=$true)][string]$TargetB64,
    [Parameter(Mandatory=$true)][string]$NewFileB64,
    [Parameter(Mandatory=$true)][string]$HelperB64,
    [Parameter(Mandatory=$true)][int]$ProcessId,
    [switch]$ElevatedRetry
)
$ErrorActionPreference = 'Stop'
function Decode([string]$value) {
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value))
}
$Target = Decode $TargetB64
$NewFile = Decode $NewFileB64
$Helper = Decode $HelperB64
$Backup = "$Target.$ProcessId.rollback"

for ($i = 0; $i -lt 80; $i++) {
    if (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 250
}

if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) {
    throw 'PC Cleaner did not exit in time for the update.'
}
if (-not (Test-Path -LiteralPath $NewFile)) {
    throw 'Downloaded update file is missing.'
}

try {
    if (Test-Path -LiteralPath $Backup) {
        Remove-Item -LiteralPath $Backup -Force -ErrorAction SilentlyContinue
    }
    Move-Item -LiteralPath $Target -Destination $Backup -Force
    $replaced = $false
    for ($i = 0; $i -lt 40; $i++) {
        try {
            Move-Item -LiteralPath $NewFile -Destination $Target -Force
            $replaced = $true
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $replaced) {
        throw 'The new executable could not replace the current one.'
    }
} catch {
    if (Test-Path -LiteralPath $Backup) {
        try { Move-Item -LiteralPath $Backup -Destination $Target -Force } catch {}
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $ElevatedRetry.IsPresent -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $args = @(
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-File', $Helper,
            '-TargetB64', $TargetB64,
            '-NewFileB64', $NewFileB64,
            '-HelperB64', $HelperB64,
            '-ProcessId', $ProcessId,
            '-ElevatedRetry'
        )
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $args
        exit 0
    }
    throw
}

Start-Process -FilePath $Target
Start-Sleep -Seconds 2
if (Test-Path -LiteralPath $Backup) {
    Remove-Item -LiteralPath $Backup -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 300
Remove-Item -LiteralPath $Helper -Force -ErrorAction SilentlyContinue
"#;
    fs::write(&helper_path, script.as_bytes())
        .map_err(|error| format!("Не удалось создать updater: {error}"))?;

    let mut command = Command::new("powershell.exe");
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        &helper_path.to_string_lossy(),
        "-TargetB64",
        &target_b64,
        "-NewFileB64",
        &downloaded_b64,
        "-HelperB64",
        &helper_b64,
        "-ProcessId",
        &process_id.to_string(),
    ]);
    command.creation_flags(0x08000000);
    command
        .spawn()
        .map_err(|error| format!("Не удалось запустить updater: {error}"))?;
    Ok(())
}

#[cfg(not(windows))]
fn launch_update_helper(
    _target: &Path,
    _downloaded: &Path,
    _process_id: u32,
) -> Result<(), String> {
    Err("Автоматическая установка обновлений доступна только в Windows.".into())
}

fn download_base64_chunk(url: &str, destination: &Path) -> Result<(), String> {
    validate_update_url(url)?;
    let url_b64 = powershell_b64(url);
    let destination_b64 = powershell_b64(&destination.display().to_string());
    let script = format!(
        "$ErrorActionPreference='Stop';         $ProgressPreference='SilentlyContinue';         $url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}'));         $out=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}'));         [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;         Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out;         if (!(Test-Path -LiteralPath $out)) {{ throw 'Фрагмент обновления не был загружен.' }}",
        url_b64, destination_b64
    );
    run_powershell_script(&script)
}

fn assemble_base64_chunks(urls: &[String], destination: &Path) -> Result<(), String> {
    if urls.is_empty() || urls.len() > 256 {
        return Err("Манифест содержит недопустимое число частей обновления.".into());
    }
    let temp_dir = env::temp_dir()
        .join("PC Cleaner")
        .join("UpdateChunks")
        .join(std::process::id().to_string());
    fs::create_dir_all(&temp_dir)
        .map_err(|error| format!("Не удалось создать временную папку частей: {error}"))?;
    let _ = fs::remove_file(destination);
    let mut output = fs::File::create(destination)
        .map_err(|error| format!("Не удалось создать файл обновления: {error}"))?;

    for (index, url) in urls.iter().enumerate() {
        let chunk_file = temp_dir.join(format!("chunk-{:04}.txt", index));
        if let Err(error) = download_base64_chunk(url, &chunk_file) {
            let _ = fs::remove_dir_all(&temp_dir);
            let _ = fs::remove_file(destination);
            return Err(format!("Загрузка части {}: {}", index + 1, error));
        }
        let encoded = fs::read_to_string(&chunk_file)
            .map_err(|error| format!("Чтение части {}: {}", index + 1, error))?;
        let compact = encoded
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .map_err(|error| format!("Некорректная Base64-часть {}: {}", index + 1, error))?;
        const MAX_CHUNK_BYTES: usize = 2 * 1024 * 1024;
        if bytes.len() > MAX_CHUNK_BYTES {
            let _ = fs::remove_dir_all(&temp_dir);
            let _ = fs::remove_file(destination);
            return Err(format!("Часть {} слишком большая.", index + 1));
        }
        use std::io::Write;
        output
            .write_all(&bytes)
            .map_err(|error| format!("Сборка части {}: {}", index + 1, error))?;
        let _ = fs::remove_file(chunk_file);
    }

    output
        .flush()
        .map_err(|error| format!("Синхронизация файла обновления: {error}"))?;
    let _ = fs::remove_dir_all(&temp_dir);
    Ok(())
}

#[tauri::command]
async fn fetch_update_manifest(url: String) -> Result<String, String> {
    validate_update_url(&url)?;
    let client = reqwest::Client::builder()
        .user_agent(format!("PC Cleaner/{}", APP_VERSION))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|error| format!("Не удалось подготовить сетевой клиент: {error}"))?;
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| format!("Не удалось получить manifest: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Сервер обновлений вернул HTTP {status}."));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("Не удалось прочитать manifest: {error}"))?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err("Manifest имеет недопустимый размер.".into());
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|error| format!("Manifest содержит недопустимые UTF-8 данные: {error}"))
}

#[tauri::command]
async fn install_update(
    app: AppHandle,
    version: String,
    url: Option<String>,
    chunks: Vec<String>,
    sha256: String,
) -> Result<String, String> {
    if !version_is_newer(&version, APP_VERSION) {
        return Err(format!(
            "Версия {} не новее установленной {}.",
            version, APP_VERSION
        ));
    }
    if url.is_none() && chunks.is_empty() {
        return Err("В манифесте нет источника обновления.".into());
    }
    if let Some(ref direct_url) = url {
        validate_update_url(direct_url)?;
    }
    for chunk_url in &chunks {
        validate_update_url(chunk_url)?;
    }
    let expected_hash = normalize_sha256(&sha256)?;

    let temp_root = env::temp_dir().join("PC Cleaner").join("Updates");
    fs::create_dir_all(&temp_root)
        .map_err(|error| format!("Не удалось создать папку обновления: {error}"))?;
    let process_id = std::process::id();
    let filename = format!(
        "PC-Cleaner-{}-{}.exe",
        version.replace(
            |ch: char| !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-',
            "_"
        ),
        process_id
    );
    let downloaded = temp_root.join(filename);
    if downloaded.exists() {
        let _ = fs::remove_file(&downloaded);
    }

    let direct_url = url.clone();
    let chunk_urls = chunks.clone();
    let downloaded_for_work = downloaded.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if let Some(direct_url) = direct_url {
            download_update(&direct_url, &downloaded_for_work)
        } else {
            assemble_base64_chunks(&chunk_urls, &downloaded_for_work)
        }
    })
    .await
    .map_err(|error| format!("Загрузка обновления: {error}"))??;

    let metadata = fs::metadata(&downloaded)
        .map_err(|error| format!("Не удалось прочитать загруженный файл: {error}"))?;
    const MAX_UPDATE_BYTES: u64 = 250 * 1024 * 1024;
    if metadata.len() == 0 || metadata.len() > MAX_UPDATE_BYTES {
        let _ = fs::remove_file(&downloaded);
        return Err("Файл обновления имеет недопустимый размер.".into());
    }

    let actual_hash = tauri::async_runtime::spawn_blocking({
        let downloaded = downloaded.clone();
        move || sha256_file(&downloaded)
    })
    .await
    .map_err(|error| format!("Проверка обновления: {error}"))??;

    if actual_hash != expected_hash {
        let _ = fs::remove_file(&downloaded);
        return Err(format!(
            "SHA-256 не совпал. Ожидался {}, получен {}.",
            expected_hash, actual_hash
        ));
    }

    let target = env::current_exe()
        .map_err(|error| format!("Не удалось определить текущий EXE: {error}"))?;
    launch_update_helper(&target, &downloaded, process_id)?;
    let _ = std::thread::Builder::new()
        .name("pc-cleaner-update-exit".into())
        .spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            app.exit(0);
        });

    Ok(format!(
        "Обновление {} проверено и подготовлено. PC Cleaner сейчас перезапустится.",
        version
    ))
}

#[tauri::command]
fn get_runtime_info() -> serde_json::Value {
    serde_json::json!({ "version": APP_VERSION, "platform": std::env::consts::OS, "arch": std::env::consts::ARCH, "quarantine": quarantine_root().display().to_string() })
}

fn storage_scan_dir(root: &Path, app: &AppHandle) -> Vec<StorageBucket> {
    let mut buckets = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return buckets;
    };
    let mut children = entries.filter_map(Result::ok).collect::<Vec<_>>();
    children.sort_by_key(|e| e.file_name().to_string_lossy().to_ascii_lowercase());
    let total = children.len() as u64;
    for (index, entry) in children.into_iter().enumerate() {
        if SCAN_CANCELLED.load(Ordering::Relaxed) {
            break;
        }
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_file() {
            buckets.push(StorageBucket {
                name: entry.file_name().to_string_lossy().to_string(),
                path: path.display().to_string(),
                size: meta.len(),
                file_count: 1,
                kind: "file".into(),
            });
            continue;
        }
        let mut size = 0u64;
        let mut files = 0u64;
        for item in WalkDir::new(&path)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if SCAN_CANCELLED.load(Ordering::Relaxed) {
                break;
            }
            if item.file_type().is_file() {
                if let Ok(m) = item.metadata() {
                    size = size.saturating_add(m.len());
                    files += 1;
                }
                if files as usize % 2500 == 0 {
                    emit_progress(
                        app,
                        "Хранилище",
                        &format!("{} · {} файлов", entry.file_name().to_string_lossy(), files),
                        index as u64,
                        total.max(1),
                        size,
                        files as usize,
                    );
                }
                if files as usize >= STORAGE_FILE_LIMIT {
                    break;
                }
            }
        }
        buckets.push(StorageBucket {
            name: entry.file_name().to_string_lossy().to_string(),
            path: path.display().to_string(),
            size,
            file_count: files,
            kind: "directory".into(),
        });
        emit_progress(
            app,
            "Хранилище",
            &format!("{} готово", entry.file_name().to_string_lossy()),
            index as u64 + 1,
            total.max(1),
            size,
            files as usize,
        );
    }
    buckets.sort_by(|a, b| b.size.cmp(&a.size));
    buckets
}

#[tauri::command]
async fn analyze_storage(
    app: AppHandle,
    path: Option<String>,
) -> Result<Vec<StorageBucket>, String> {
    SCAN_CANCELLED.store(false, Ordering::Relaxed);
    let target = path.unwrap_or_else(|| String::from(r#"C:\"#));
    let target_path = PathBuf::from(&target);
    if !target_path.is_dir()
        || normalize_path(&target_path).len() < 3
        || !normalize_path(&target_path).starts_with(r#"c:\"#)
    {
        return Err("Для анализа доступен только существующий каталог на диске C:".into());
    }
    tauri::async_runtime::spawn_blocking(move || Ok(storage_scan_dir(&target_path, &app)))
        .await
        .map_err(|err| format!("Анализ хранилища завершился с ошибкой: {err}"))?
}

fn browser_cache_roots() -> Vec<(String, PathBuf, bool)> {
    let mut roots = Vec::new();
    if let Some(local) = path_from_env("LOCALAPPDATA") {
        for (name, path) in [
            (
                "Google Chrome",
                local.join("Google/Chrome/User Data/Default/Cache"),
            ),
            (
                "Microsoft Edge",
                local.join("Microsoft/Edge/User Data/Default/Cache"),
            ),
        ] {
            if path.exists() {
                roots.push((name.into(), path, true));
            }
        }
        let firefox = local.join("Mozilla/Firefox/Profiles");
        if firefox.exists() {
            for entry in WalkDir::new(&firefox)
                .max_depth(2)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
                if entry.file_type().is_dir() && entry.file_name() == "cache2" {
                    roots.push(("Mozilla Firefox".into(), entry.path().to_path_buf(), false));
                }
            }
        }
    }
    roots
}

fn browser_profile_dirs(browser: &str) -> Vec<PathBuf> {
    let mut profiles = Vec::new();
    let Some(local) = path_from_env("LOCALAPPDATA") else {
        return profiles;
    };
    let base = match browser {
        "Google Chrome" => local.join("Google/Chrome/User Data"),
        "Microsoft Edge" => local.join("Microsoft/Edge/User Data"),
        _ => return profiles,
    };
    let Ok(entries) = fs::read_dir(base) else {
        return profiles;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "Default" || name.starts_with("Profile ") {
            profiles.push(path);
        }
    }
    profiles
}

fn browser_data_candidates(browser: &str) -> Vec<(String, PathBuf, bool)> {
    let mut result = Vec::new();
    if browser == "Mozilla Firefox" {
        let Some(local) = path_from_env("LOCALAPPDATA") else {
            return result;
        };
        let base = local.join("Mozilla/Firefox/Profiles");
        if let Ok(entries) = fs::read_dir(base) {
            for entry in entries.filter_map(Result::ok) {
                let profile = entry.path();
                if !profile.is_dir() {
                    continue;
                }
                let files = [
                    ("Cookies", profile.join("cookies.sqlite")),
                    ("History", profile.join("places.sqlite")),
                    ("Downloads metadata", profile.join("places.sqlite")),
                    ("Site data", profile.join("storage")),
                ];
                for (category, path) in files {
                    if path.exists() {
                        result.push((category.into(), path, true));
                    }
                }
            }
        }
        return result;
    }
    for profile in browser_profile_dirs(browser) {
        let files = [
            (
                "Cookies",
                vec![profile.join("Network/Cookies"), profile.join("Cookies")],
            ),
            ("History", vec![profile.join("History")]),
            ("Downloads metadata", vec![profile.join("History")]),
            (
                "Site data",
                vec![
                    profile.join("Local Storage"),
                    profile.join("IndexedDB"),
                    profile.join("Service Worker/CacheStorage"),
                ],
            ),
        ];
        for (category, paths) in files {
            for path in paths {
                if path.exists() {
                    result.push((category.into(), path, true));
                }
            }
        }
    }
    result
}

fn browser_data_summary() -> Vec<BrowserDataInfo> {
    let mut out = Vec::new();
    for browser in ["Google Chrome", "Microsoft Edge", "Mozilla Firefox"] {
        let mut seen = HashSet::new();
        for (category, path, risky) in browser_data_candidates(browser) {
            let key = normalize_path(&path);
            if !seen.insert((category.clone(), key)) {
                continue;
            }
            let (size, file_count) = if path.is_dir() {
                measure_directory(&path)
            } else {
                (fs::metadata(&path).map(|m| m.len()).unwrap_or(0), 1)
            };
            out.push(BrowserDataInfo {
                browser: browser.into(),
                category,
                path: path.display().to_string(),
                size,
                file_count,
                risky,
            });
        }
    }
    out
}

fn collect_browser_data_items(
    browser: &str,
    categories: &[String],
    settings: &CleanerSettings,
) -> Vec<CleanupItem> {
    let wanted: HashSet<String> = categories.iter().cloned().collect();
    let mut paths = HashSet::new();
    for (category, root, _risky) in browser_data_candidates(browser) {
        if !wanted.contains(&category) || is_excluded(&root, settings) {
            continue;
        }
        if root.is_file() {
            paths.insert(root);
            continue;
        }
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file() {
                paths.insert(entry.path().to_path_buf());
            }
        }
    }
    let mut out = Vec::new();
    for path in paths {
        if is_excluded(&path, settings) {
            continue;
        }
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if meta.len() == 0 {
            continue;
        }
        out.push(CleanupItem {
            id: format!(
                "browser-data-{}",
                blake3::hash(path.to_string_lossy().as_bytes()).to_hex()
            ),
            path: path.display().to_string(),
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            category: "Данные браузера".into(),
            reason: format!("{}: {}", browser, categories.join(", ")),
            size: meta.len(),
            safe_to_delete: true,
            confidence: "после предупреждения".into(),
        });
    }
    out
}

fn measure_directory(path: &Path) -> (u64, u64) {
    let mut size = 0u64;
    let mut count = 0u64;
    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        if entry.file_type().is_file() {
            if let Ok(meta) = entry.metadata() {
                size = size.saturating_add(meta.len());
                count += 1;
            }
        }
    }
    (size, count)
}

#[tauri::command]
async fn browser_caches() -> Result<Vec<BrowserCacheInfo>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        Ok(browser_cache_roots()
            .into_iter()
            .map(|(browser, path, _)| {
                let (size, file_count) = measure_directory(&path);
                BrowserCacheInfo {
                    browser,
                    path: path.display().to_string(),
                    size,
                    file_count,
                }
            })
            .collect())
    })
    .await
    .map_err(|err| format!("Анализ браузеров завершился с ошибкой: {err}"))?
}

#[tauri::command]
async fn browser_data_summary_cmd() -> Result<Vec<BrowserDataInfo>, String> {
    tauri::async_runtime::spawn_blocking(browser_data_summary)
        .await
        .map_err(|err| format!("Анализ данных браузеров завершился с ошибкой: {err}"))
}

#[tauri::command]
async fn cleanup_browser_data(
    browser: String,
    categories: Vec<String>,
    confirmed: bool,
) -> Result<CleanupReport, String> {
    if !confirmed {
        return Err("Требуется явное подтверждение очистки данных браузера".into());
    }
    let settings = read_settings();
    if !cleanup_category_allowed("Данные браузера", &settings) {
        return Err("Очистка cookies/history/site data отключена в настройках".into());
    }
    let items = tauri::async_runtime::spawn_blocking(move || {
        collect_browser_data_items(&browser, &categories, &settings)
    })
    .await
    .map_err(|err| format!("Подготовка данных браузера: {err}"))?;
    tauri::async_runtime::spawn_blocking(move || cleanup_sync(items))
        .await
        .map_err(|err| format!("Очистка данных браузера: {err}"))?
}

#[tauri::command]
async fn cleanup_browser_caches() -> Result<CleanupReport, String> {
    let settings = read_settings();
    let items = tauri::async_runtime::spawn_blocking(move || {
        let mut out = Vec::new();
        for (browser, path, safe) in browser_cache_roots() {
            if !safe || is_excluded(&path, &settings) {
                continue;
            }
            for entry in WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
                let p = entry.path();
                if !entry.file_type().is_file() || is_excluded(p, &settings) {
                    continue;
                }
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                if is_recent_with_settings(&meta, &settings) || meta.len() == 0 {
                    continue;
                }
                out.push(CleanupItem {
                    id: blake3::hash(p.to_string_lossy().as_bytes())
                        .to_hex()
                        .to_string(),
                    path: p.display().to_string(),
                    name: p
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    category: "Кэш браузера".into(),
                    reason: format!("Кэш {browser}"),
                    size: meta.len(),
                    safe_to_delete: true,
                    confidence: "высокая".into(),
                });
            }
        }
        out
    })
    .await
    .map_err(|err| format!("Подготовка очистки браузеров: {err}"))?;
    tauri::async_runtime::spawn_blocking(move || cleanup_sync(items))
        .await
        .map_err(|err| format!("Очистка браузеров: {err}"))?
}

#[cfg(windows)]
fn empty_recycle_bin_sync() -> Result<(), String> {
    use std::ptr;
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHEmptyRecycleBinW(hwnd: *mut std::ffi::c_void, root: *const u16, flags: u32) -> i32;
    }
    let root: Vec<u16> = std::ffi::OsStr::new(r#"C:\"#)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let hr = unsafe { SHEmptyRecycleBinW(ptr::null_mut(), root.as_ptr(), 1 | 2 | 4) };
    if hr == 0 {
        Ok(())
    } else {
        Err(format!("Не удалось очистить корзину. HRESULT: 0x{hr:08X}"))
    }
}

#[cfg(not(windows))]
fn empty_recycle_bin_sync() -> Result<(), String> {
    Err("Очистка корзины доступна только в Windows".into())
}

#[tauri::command]
fn empty_recycle_bin() -> Result<(), String> {
    empty_recycle_bin_sync()?;
    let _ = append_action("Корзина", "Корзина диска C:", 0);
    Ok(())
}

fn cleanup_sync(items: Vec<CleanupItem>) -> Result<CleanupReport, String> {
    let settings = read_settings();
    let mut report = CleanupReport::default();
    let mut seen = HashSet::new();
    for item in items {
        let key = normalize_path(Path::new(&item.path));
        if !seen.insert(key) {
            continue;
        }
        if !item.safe_to_delete {
            report.failed_items += 1;
            report
                .failures
                .push(format!("Пропущено небезопасное: {}", item.path));
            continue;
        }
        if !cleanup_category_allowed(&item.category, &settings) {
            report.failed_items += 1;
            report.failures.push(format!(
                "Категория запрещена настройками: {}",
                item.category
            ));
            continue;
        }
        let source = PathBuf::from(&item.path);
        if item.category == "Дубликаты" && is_protected_duplicate_path(&source) {
            report.failed_items += 1;
            report.failures.push(format!(
                "Защищённая папка: дубликат не удалён — {}",
                item.path
            ));
            continue;
        }
        if is_excluded(&source, &settings) {
            report.failed_items += 1;
            report
                .failures
                .push(format!("Исключено настройками: {}", item.path));
            continue;
        }
        let Ok(meta) = fs::metadata(&source) else {
            report.failed_items += 1;
            report
                .failures
                .push(format!("Файл недоступен: {}", item.path));
            continue;
        };
        if is_recent_with_settings(&meta, &settings) {
            report.failed_items += 1;
            report
                .failures
                .push(format!("Недавний файл защищён: {}", item.path));
            continue;
        }
        let current_item = CleanupItem {
            size: meta.len(),
            ..item
        };
        match fs::remove_file(&source) {
            Ok(_) => {
                report.deleted_items += 1;
                report.deleted_bytes = report.deleted_bytes.saturating_add(current_item.size);
                let _ = append_action("Удаление", &current_item.path, current_item.size);
            }
            Err(_err) if !source.exists() => {
                report.failed_items += 1;
                report
                    .failures
                    .push(format!("Файл уже отсутствует: {}", current_item.path));
            }
            Err(err) => {
                report.failed_items += 1;
                report
                    .failures
                    .push(format!("Не удалось удалить {}: {}", current_item.path, err));
            }
        }
    }
    if report.deleted_items > 0 {
        let _ = append_action(
            "Очистка",
            &format!("Безвозвратно удалено: {} файлов", report.deleted_items),
            report.deleted_bytes,
        );
    }
    Ok(report)
}

#[tauri::command]
async fn cleanup(items: Vec<CleanupItem>) -> Result<CleanupReport, String> {
    tauri::async_runtime::spawn_blocking(move || cleanup_sync(items))
        .await
        .map_err(|err| format!("Очистка завершилась с ошибкой: {err}"))?
}

#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    let manager = app.autolaunch();
    if enabled {
        manager.enable().map_err(|e| e.to_string())?;
    } else {
        manager.disable().map_err(|e| e.to_string())?;
    }
    Ok(enabled)
}

#[tauri::command]
fn is_autostart_enabled(app: AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

fn configure_smart_task(settings: &CleanerSettings) -> Result<(), String> {
    #[cfg(windows)]
    {
        if !settings.smart_clean_enabled {
            let _ = Command::new("schtasks")
                .args(["/Delete", "/TN", SMART_TASK_NAME, "/F"])
                .output();
            return Ok(());
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let days = settings.smart_clean_days.join(",");
        let tr = format!("\\\"{}\\\" --smart-clean", exe.display());
        let status = Command::new("schtasks")
            .args([
                "/Create",
                "/SC",
                "WEEKLY",
                "/MO",
                "1",
                "/D",
                &days,
                "/ST",
                &settings.smart_clean_time,
                "/TN",
                SMART_TASK_NAME,
                "/TR",
                &tr,
                "/F",
            ])
            .status()
            .map_err(|e| format!("Планировщик задач: {e}"))?;
        if !status.success() {
            return Err(format!("Планировщик задач вернул код {:?}", status.code()));
        }
    }
    Ok(())
}

#[tauri::command]
fn save_smart_schedule(settings: CleanerSettings) -> Result<CleanerSettings, String> {
    let saved = save_settings(settings)?;
    configure_smart_task(&saved)?;
    Ok(saved)
}

fn duplicate_cleanup_items_silent(settings: &CleanerSettings) -> Vec<CleanupItem> {
    let mut by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    for root in analysis_roots() {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if !entry.file_type().is_file() || is_excluded(path, settings) {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.len() < MIN_DUPLICATE_SIZE || is_recent_with_settings(&meta, settings) {
                continue;
            }
            by_size
                .entry(meta.len())
                .or_default()
                .push(path.to_path_buf());
        }
    }
    let mut out = Vec::new();
    for (size, paths) in by_size.into_iter().filter(|(_, p)| p.len() > 1) {
        let mut by_hash: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for path in paths {
            if let Some(hash) = hash_file(&path) {
                by_hash.entry(hash).or_default().push(path);
            }
        }
        for (_, same) in by_hash.into_iter().filter(|(_, p)| p.len() > 1) {
            let mut ordered = same
                .into_iter()
                .filter_map(|path| {
                    let meta = fs::metadata(&path).ok()?;
                    Some((path, file_modified_unix(&meta)))
                })
                .collect::<Vec<_>>();
            ordered.sort_by(|a, b| b.1.unwrap_or(0).cmp(&a.1.unwrap_or(0)));
            for (path, _) in ordered.into_iter().skip(1) {
                out.push(CleanupItem {
                    id: format!(
                        "smart-duplicate-{}",
                        blake3::hash(path.to_string_lossy().as_bytes()).to_hex()
                    ),
                    path: path.display().to_string(),
                    name: path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    category: "Дубликаты".into(),
                    reason: "Точная копия; Smart Clean оставляет самую новую".into(),
                    size,
                    safe_to_delete: true,
                    confidence: "высокая".into(),
                });
            }
        }
    }
    out
}

fn smart_clean_sync() -> Result<CleanupReport, String> {
    let settings = read_settings();
    let mut items = Vec::new();
    for (root, category, safe, reason) in configured_junk_roots(&settings) {
        if !safe {
            continue;
        }
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if !entry.file_type().is_file() || is_excluded(path, &settings) {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if is_recent_with_settings(&meta, &settings) || meta.len() == 0 {
                continue;
            }
            items.push(CleanupItem {
                id: blake3::hash(path.to_string_lossy().as_bytes())
                    .to_hex()
                    .to_string(),
                path: path.display().to_string(),
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                category: category.into(),
                reason: reason.into(),
                size: meta.len(),
                safe_to_delete: true,
                confidence: "высокая".into(),
            });
        }
    }
    if settings.smart_clean_include_duplicates && settings.scan_duplicates {
        items.extend(duplicate_cleanup_items_silent(&settings));
    }
    let max_bytes = settings
        .smart_clean_max_gb
        .saturating_mul(1024 * 1024 * 1024);
    let mut selected_bytes = 0u64;
    let before_limit = items.len();
    items.retain(|item| {
        if !cleanup_category_allowed(&item.category, &settings) {
            return false;
        }
        if selected_bytes.saturating_add(item.size) > max_bytes {
            return false;
        }
        selected_bytes = selected_bytes.saturating_add(item.size);
        true
    });
    if items.len() < before_limit {
        let _ = append_action(
            "Smart Clean",
            &format!(
                "Применён лимит {} GB; часть элементов отложена",
                settings.smart_clean_max_gb
            ),
            0,
        );
    }
    let report = cleanup_sync(items)?;
    let _ = append_action("Автоочистка", "Smart Clean", report.deleted_bytes);
    Ok(report)
}

#[tauri::command]
async fn smart_clean_now() -> Result<CleanupReport, String> {
    tauri::async_runtime::spawn_blocking(smart_clean_sync)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
fn open_path(path: String) -> Result<(), String> {
    let target = PathBuf::from(path);
    if !target.exists() {
        return Err("Путь больше не существует".into());
    }
    #[cfg(windows)]
    {
        Command::new("explorer.exe")
            .arg(target)
            .status()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Разрешены только HTTP(S)-ссылки".into());
    }
    #[cfg(windows)]
    {
        Command::new("explorer.exe")
            .arg(&url)
            .status()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn list_quarantine() -> Result<Vec<QuarantineItem>, String> {
    let settings = read_settings();
    let _ = purge_expired_quarantine(&settings)?;
    Ok(read_quarantine_manifest()
        .into_iter()
        .filter(|item| Path::new(&item.quarantine_path).is_file())
        .collect())
}

#[tauri::command]
fn list_activity() -> Result<Vec<ActionLogEntry>, String> {
    let mut log = read_action_log();
    log.reverse();
    Ok(log)
}

#[tauri::command]
fn restore_quarantine(ids: Vec<String>) -> Result<CleanupReport, String> {
    let mut report = CleanupReport::default();
    let mut manifest = read_quarantine_manifest();
    let wanted: HashSet<String> = ids.into_iter().collect();
    let mut remaining = Vec::new();

    for item in manifest.drain(..) {
        if !wanted.contains(&item.id) {
            remaining.push(item);
            continue;
        }

        let source = PathBuf::from(&item.quarantine_path);
        let destination = PathBuf::from(&item.original_path);
        if !source.is_file() {
            report.failed_items += 1;
            report
                .failures
                .push(format!("В карантине не найдено: {}", item.name));
            continue;
        }
        if destination.exists() {
            report.failed_items += 1;
            report.failures.push(format!(
                "Восстановление отменено, файл уже существует: {}",
                item.original_path
            ));
            remaining.push(item);
            continue;
        }
        if let Some(parent) = destination.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::rename(&source, &destination) {
            Ok(_) => {
                report.deleted_items += 1;
                report.deleted_bytes = report.deleted_bytes.saturating_add(item.size);
                let _ = append_action("Восстановление", &item.original_path, item.size);
            }
            Err(err) => {
                report.failed_items += 1;
                report.failures.push(format!(
                    "Не удалось восстановить {}: {}",
                    item.original_path, err
                ));
                remaining.push(item);
            }
        }
    }

    write_quarantine_manifest(&remaining)?;
    Ok(report)
}

#[tauri::command]
fn read_image_preview(path: String) -> Result<Option<String>, String> {
    let file = PathBuf::from(path);
    if !file.is_file() {
        return Ok(None);
    }
    let ext = file
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mime = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        _ => return Ok(None),
    };
    let meta = fs::metadata(&file).map_err(|e| e.to_string())?;
    if meta.len() > 5 * 1024 * 1024 {
        return Ok(None);
    }
    let bytes = fs::read(&file).map_err(|e| e.to_string())?;
    Ok(Some(format!(
        "data:{mime};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )))
}

#[tauri::command]
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    if std::env::args().any(|arg| arg == "--smart-clean") {
        let _ = smart_clean_sync();
        return;
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None::<Vec<&'static str>>,
        ))
        .setup(|app| {
            use tauri::menu::{Menu, MenuItem};
            use tauri::tray::TrayIconBuilder;
            let open = MenuItem::with_id(app, "open", "Открыть PC Cleaner", true, None::<&str>)?;
            let scan = MenuItem::with_id(app, "scan", "Сканировать", true, None::<&str>)?;
            let smart = MenuItem::with_id(app, "smart", "Smart Clean", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Выйти", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &scan, &smart, &quit])?;
            let mut tray = TrayIconBuilder::with_id("main")
                .menu(&menu)
                .show_menu_on_left_click(false);
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.on_menu_event(|app, event| match event.id.as_ref() {
                "open" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.unminimize();
                        let _ = window.set_focus();
                    }
                }
                "scan" => {
                    let _ = app.emit("tray-scan-request", ());
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "smart" => {
                    let handle = app.clone();
                    tauri::async_runtime::spawn_blocking(move || {
                        let result = smart_clean_sync();
                        let _ = handle.emit("smart-clean-result", result.ok());
                    });
                }
                "quit" => app.exit(0),
                _ => (),
            })
            .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if read_settings().minimize_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            scan_system,
            scan_duplicates_only,
            cancel_scan,
            cleanup,
            list_quarantine,
            list_activity,
            restore_quarantine,
            get_settings,
            save_settings,
            save_smart_schedule,
            set_autostart,
            is_autostart_enabled,
            smart_clean_now,
            analyze_storage,
            browser_caches,
            browser_data_summary_cmd,
            cleanup_browser_data,
            cleanup_browser_caches,
            empty_recycle_bin,
            open_path,
            open_url,
            read_image_preview,
            app_version,
            fetch_update_manifest,
            install_update,
            get_runtime_info,
            format_bytes
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
