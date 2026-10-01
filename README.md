# PC Cleaner

PC Cleaner is a Windows desktop cleanup utility built with Tauri.

## Repository isolation

This repository is dedicated only to PC Cleaner. Its source code, CI workflow, GitHub Releases, and update channel are independent from every other project.

## Release flow

1. Update the application version in `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json`.
2. Create a matching Git tag such as `v0.3.2`.
3. Push the tag to GitHub.
4. GitHub Actions builds the Windows x64 EXE and NSIS installer.
5. The workflow creates a GitHub Release and uploads:
   - `PC-Cleaner-<version>-x64.exe`
   - `PC-Cleaner-<version>-x64-setup.exe`
   - `latest.json`
6. PC Cleaner checks `releases/latest/download/latest.json`, verifies SHA-256, and can install a newer EXE automatically.

The release workflow lives at `.github/workflows/release.yml`.

## Update channel

The application uses the repository's own GitHub Releases as its update source. No other project repository is used for PC Cleaner updates.
