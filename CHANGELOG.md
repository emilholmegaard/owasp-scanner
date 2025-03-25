# Changelog

All notable changes to the OWASP Scanner project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial changelog file
- Performance tuning configuration options for scanner
  - Added `ScannerConfig` class with options for parallel processing, thread count, file caching, etc.
  - Added command-line options for configuring performance: `--fast`, `--thorough`, `--threads=N`, etc.
  - Added preset configurations for different scan types (fast, thorough, default)

### Performance
- Optimized context analysis in security rules with caching
- Added `getJoinedLinesAround` method to RuleContext interface
- Improved pattern matching in security rules using combined patterns
- Implemented configurable parallel processing with thread count control
- Added file size limiting for large codebases
- Added early termination option to stop scanning files after finding a threshold of violations

## How this changelog is generated

This changelog is automatically generated as part of the release process using GitHub Actions. The action analyzes commit messages between releases to create structured entries.

For best results when making commits, please use conventional commit messages with one of these prefixes:
- `feat:` - A new feature
- `fix:` - A bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring without changes to functionality
- `perf:` - Performance improvements
- `test:` - Adding or updating tests
- `build:` - Changes to build process or tools
- `ci:` - Changes to CI/CD workflows
- `chore:` - Other changes that don't modify src or test files

Example: `feat: Add support for Python file scanning`
