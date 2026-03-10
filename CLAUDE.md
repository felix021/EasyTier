# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

EasyTier is a decentralized P2P VPN solution written in Rust with Tokio. It enables creating full meshed VPN networks with NAT traversal, WireGuard integration, and cross-platform support.

## Build Commands

### Core (Rust)
```bash
# Standard release build
cargo build --release

# Build with all features
cargo build --release --features full

# Platform-specific (see .cargo/config.toml for targets)
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-pc-windows-msvc
```

Build artifacts: `target/[target-triple]/release/` (easytier-core, easytier-cli, easytier-web)

### GUI (Tauri + Vue)
```bash
# Install frontend dependencies
pnpm -r install

# Build frontend
pnpm -r build

# Build Tauri application
cd easytier-gui
pnpm tauri build --target x86_64-unknown-linux-gnu
```

Build artifacts: `easytier-gui/src-tauri/target/release/bundle/`

### Android
```bash
cd easytier-gui
pnpm tauri android build
```

## Test Commands

```bash
# System configuration (Linux, required before tests)
sudo modprobe br_netfilter
sudo sysctl net.bridge.bridge-nf-call-iptables=0
sudo sysctl net.bridge.bridge-nf-call-ip6tables=0

# Run all tests with full features
cargo test --no-default-features --features=full --verbose

# Run specific test
cargo test --no-default-features --features=full test_name --verbose

# Using cargo-nextest (preferred)
cargo nextest run --package easytier --features full
```

Tests are located in `easytier/src/tests/`.

## Lint Commands

```bash
# Rust formatting
cargo fmt --all -- --check

# Rust linting (clippy)
cargo clippy --all-targets --features full --all -- -D warnings

# Frontend linting
pnpm lint
pnpm lint:fix
```

## Architecture

### Workspace Structure (Cargo.toml)
- **easytier**: Core library and CLI binaries (easytier-core, easytier-cli)
- **easytier-web**: Web dashboard server (Axum + Vue)
- **easytier-gui/src-tauri**: Desktop GUI (Tauri 2.x)
- **easytier-rpc-build**: Protobuf RPC code generator
- **easytier-contrib/**: Third-party integrations (FFI, Android JNI, OpenHarmony)

### Core Components (easytier/src/)
- **launcher.rs**: Configuration and startup
- **core.rs**: Main event loop
- **connector/**: Connection establishment (TCP, UDP, DNS, HTTP, hole punching)
- **tunnel/**: Data transport protocols (TCP, UDP, WebSocket, WireGuard, QUIC, fake_tcp)
- **peers/**: Peer management, OSPF routing, ACL filtering, encryption
- **vpn_portal/**: WireGuard VPN portal server
- **gateway/**: Subnet proxy gateway
- **rpc_service/**: gRPC/protobuf RPC services
- **proto/**: Protocol buffer definitions (*.proto)

### Frontend (pnpm monorepo)
- **easytier-web/frontend**: Main web dashboard (Vue 3 + PrimeVue)
- **easytier-web/frontend-lib**: Shared component library
- **easytier-gui**: Desktop GUI frontend

## Feature Flags (easytier crate)

| Feature | Description |
|---------|-------------|
| `default` | wireguard, websocket, smoltcp, tun, socks5, kcp, quic, faketcp, magic-dns, zstd |
| `full` | All default + aes-gcm, openssl-crypto |
| `wireguard` | WireGuard protocol support |
| `quic` | QUIC protocol (quinn) |
| `tun` | TUN device support |

## Development Environment

Required tools:
- Rust 1.93
- Node.js v21+ (v22 recommended)
- pnpm v9+
- LLVM/Clang
- Protoc (Protocol Buffers compiler)

Linux dependencies:
```bash
sudo apt-get install musl-tools llvm clang protobuf-compiler
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
    libgtk-3-dev librsvg2-dev libxdo-dev libssl-dev libappindicator3-dev patchelf
```

Nix development shells available via `flake.nix`: `core`, `web`, `gui`, `android`, `full`.

## Git Workflow

- Feature branches from `develop`
- PRs target `develop` branch
- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`

## Key File Locations

- Protobuf definitions: `easytier/src/proto/*.proto`
- Build script (protobuf generation): `easytier/build.rs`
- Cross-compilation config: `.cargo/config.toml`
- CI/CD workflows: `.github/workflows/`
- Database migrations: `easytier-web/migrations/`
