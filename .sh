#!/usr/bin/env bash
# ==============================================================================
# TITAN SOVEREIGN MESH - Full Stack Onboarding Script
# Author: Julius Cameron Hill / TitanU AI LLC
# Patent Refs: JCH-2026-004 (ZK-Audit), JCH-2026-006 (Rhea Consent Engine)
# Stack: Rust + Go + Kotlin + Julia + Kafka + Tokio + Headscale + PostgreSQL
# Target: Termux / ARM64 Android (aarch64) — Zero Root Required
# ==============================================================================
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
NC='\033[0m'; BOLD='\033[1m'

# ── Config ────────────────────────────────────────────────────────────────────
MESH_VERSION="2.0.0-sovereign"
CONTROL_PLANE="hs.wecanjuschill.net"
KAFKA_PORT=9092
POSTGRES_PORT=5432
TOKIO_API_PORT=8080
KOTLIN_PORT=8081
JULIA_PORT=8082
WORKSPACE="$HOME/titan-mesh"
KEYS_DIR="$WORKSPACE/.keys"
LOG_FILE="$HOME/.titan_mesh_audit.log"
PROOT_DISTRO="ubuntu"

# ── ZK Audit State Ledger (JCH-2026-004) ─────────────────────────────────────
zk_log() {
    local event="$1"
    local payload="$2"
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local device_id
    device_id=$(cat "$KEYS_DIR/device.id" 2>/dev/null || echo "UNBOUND")
    local entry="[ZK-AUDIT] ts=${ts} device=${device_id} event=${event} payload=${payload}"
    local hash
    hash=$(echo "$entry" | sha256sum | awk '{print $1}')
    echo "${entry} hash=${hash}" >> "$LOG_FILE"
    echo -e "  ${MAGENTA}[ZK]${NC} ${event} → ${hash:0:16}..."
}

# ── Banner ────────────────────────────────────────────────────────────────────
banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ████████╗██╗████████╗ █████╗ ███╗   ██╗"
    echo "  ╚══██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║"
    echo "     ██║   ██║   ██║   ███████║██╔██╗ ██║"
    echo "     ██║   ██║   ██║   ██╔══██║██║╚██╗██║"
    echo "     ██║   ██║   ██║   ██║  ██║██║ ╚████║"
    echo "     ╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝"
    echo "  ── SOVEREIGN MESH NODE v${MESH_VERSION} ──"
    echo "  Control Plane: ${CONTROL_PLANE}"
    echo -e "${NC}"
}

# ── Step Logger ───────────────────────────────────────────────────────────────
step() { echo -e "\n${BLUE}${BOLD}[★] $1${NC}"; }
ok()   { echo -e "  ${GREEN}[✓]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
err()  { echo -e "  ${RED}[✗]${NC} $1"; }
info() { echo -e "  ${CYAN}[-]${NC} $1"; }

# ── Device Fingerprint (Zero-Touch Hardware Bind) ─────────────────────────────
bind_device() {
    step "Binding Hardware Identity"
    mkdir -p "$KEYS_DIR"
    chmod 700 "$KEYS_DIR"

    if [ -f "$KEYS_DIR/device.id" ]; then
        ok "Existing device ID found: $(cat "$KEYS_DIR/device.id")"
        return
    fi

    # Build hardware-bound ID from available entropy sources
    local raw=""
    # Android ID via Termux API (best source)
    if command -v termux-telephony-deviceinfo &>/dev/null; then
        raw=$(termux-telephony-deviceinfo 2>/dev/null | grep -i imei | head -1 | tr -d '": ,' || true)
    fi
    # Fallback: MAC + hostname + uptime entropy
    if [ -z "$raw" ]; then
        raw=$(cat /proc/net/if_inet6 2>/dev/null | head -1 || true)
        raw="${raw}$(hostname 2>/dev/null || true)"
        raw="${raw}$(cat /proc/uptime 2>/dev/null | awk '{print $2}' || true)"
    fi
    # Final fallback: pure entropy
    if [ -z "$raw" ]; then
        raw=$(head -c 32 /dev/urandom | sha256sum | awk '{print $1}')
    fi

    local device_id
    device_id="TITAN-$(echo "$raw" | sha256sum | awk '{print $1}' | head -c 16 | tr '[:lower:]' '[:upper:]')"
    echo "$device_id" > "$KEYS_DIR/device.id"
    chmod 600 "$KEYS_DIR/device.id"
    ok "Device ID bound: $device_id"
    zk_log "DEVICE_BIND" "$device_id"
}

# ── WireGuard Key Generation ──────────────────────────────────────────────────
gen_wireguard_keys() {
    step "Generating WireGuard Keypair"

    if [ -f "$KEYS_DIR/wg.private" ]; then
        ok "WireGuard keys already exist"
        return
    fi

    if command -v wg &>/dev/null; then
        wg genkey > "$KEYS_DIR/wg.private"
        wg pubkey < "$KEYS_DIR/wg.private" > "$KEYS_DIR/wg.public"
        chmod 600 "$KEYS_DIR/wg.private"
        ok "WireGuard private key: $(head -c 8 "$KEYS_DIR/wg.private")..."
        ok "WireGuard public key:  $(cat "$KEYS_DIR/wg.public")"
        zk_log "WG_KEYGEN" "pubkey=$(cat "$KEYS_DIR/wg.public")"
    else
        # Generate a pre-shared key using OpenSSL as fallback
        openssl rand -base64 32 > "$KEYS_DIR/wg.psk"
        chmod 600 "$KEYS_DIR/wg.psk"
        warn "wireguard-tools not available — PSK generated for Headscale pre-auth"
        ok "PSK stored at $KEYS_DIR/wg.psk"
        zk_log "WG_PSK_FALLBACK" "psk_generated"
    fi
}

# ── Headscale Registration (replaces raw IP) ──────────────────────────────────
register_headscale() {
    step "Registering with Headscale Control Plane: $CONTROL_PLANE"

    local device_id
    device_id=$(cat "$KEYS_DIR/device.id")

    # Build enrollment payload
    local payload
    payload=$(cat <<EOF
{
  "device_id": "${device_id}",
  "mesh_version": "${MESH_VERSION}",
  "arch": "$(uname -m)",
  "os": "termux-android",
  "services": ["kafka","postgres","tokio-api","kotlin-ktor","julia-http"],
  "control_plane": "${CONTROL_PLANE}",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
)

    echo "$payload" > "$KEYS_DIR/enrollment.json"
    chmod 600 "$KEYS_DIR/enrollment.json"

    # Attempt Headscale pre-auth enrollment
    if command -v curl &>/dev/null; then
        local response
        response=$(curl -sf \
            --max-time 10 \
            -X POST \
            -H "Content-Type: application/json" \
            -H "X-Device-ID: ${device_id}" \
            -d "$payload" \
            "https://${CONTROL_PLANE}/api/v1/enroll" 2>/dev/null || echo "OFFLINE")

        if [ "$response" != "OFFLINE" ] && [ -n "$response" ]; then
            echo "$response" > "$KEYS_DIR/enrollment_response.json"
            ok "Enrolled with control plane"
            zk_log "HEADSCALE_ENROLLED" "response_stored"
        else
            warn "Control plane unreachable — node will operate in sovereign offline mode"
            zk_log "HEADSCALE_OFFLINE" "sovereign_mode_active"
        fi
    else
        warn "curl not available — skipping remote enrollment"
    fi

    ok "Enrollment payload written to $KEYS_DIR/enrollment.json"
}

# ── PostgreSQL Init ───────────────────────────────────────────────────────────
init_postgres() {
    step "Initializing PostgreSQL (Sovereign State Store)"

    if ! command -v pg_ctl &>/dev/null; then
        warn "PostgreSQL not installed — skipping"
        return
    fi

    local pg_data="$WORKSPACE/pgdata"
    if [ ! -d "$pg_data" ]; then
        initdb -D "$pg_data" --no-locale --encoding=UTF8 -U titan 2>/dev/null
        ok "PostgreSQL cluster initialized"
    else
        ok "PostgreSQL cluster already exists"
    fi

    # Titan mesh schema bootstrap
    local pg_conf="$pg_data/postgresql.conf"
    grep -q "titan_mesh" "$pg_conf" 2>/dev/null || cat >> "$pg_conf" <<EOF

# TitanU Sovereign Mesh Config
listen_addresses = '127.0.0.1'
port = ${POSTGRES_PORT}
log_destination = 'stderr'
logging_collector = off
EOF

    # Start if not running
    if ! pg_ctl status -D "$pg_data" &>/dev/null; then
        pg_ctl start -D "$pg_data" -l "$WORKSPACE/postgres.log" -o "-p $POSTGRES_PORT" &>/dev/null || true
        sleep 2
    fi

    # Bootstrap schema
    if pg_ctl status -D "$pg_data" &>/dev/null; then
        psql -U titan -p "$POSTGRES_PORT" -d postgres -tc \
            "SELECT 1 FROM pg_database WHERE datname='titan_mesh'" 2>/dev/null | grep -q 1 || \
        psql -U titan -p "$POSTGRES_PORT" -d postgres \
            -c "CREATE DATABASE titan_mesh;" 2>/dev/null || true

        psql -U titan -p "$POSTGRES_PORT" -d titan_mesh 2>/dev/null <<SQLEOF || true
CREATE TABLE IF NOT EXISTS zk_audit_ledger (
    id          SERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    device_id   TEXT NOT NULL,
    event       TEXT NOT NULL,
    payload     TEXT,
    hash        TEXT NOT NULL,
    chain_hash  TEXT
);

CREATE TABLE IF NOT EXISTS mesh_nodes (
    id          SERIAL PRIMARY KEY,
    device_id   TEXT UNIQUE NOT NULL,
    enrolled_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen   TIMESTAMPTZ,
    services    JSONB,
    status      TEXT DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS kafka_events (
    id          BIGSERIAL PRIMARY KEY,
    topic       TEXT NOT NULL,
    payload     JSONB,
    produced_at TIMESTAMPTZ DEFAULT NOW(),
    consumed    BOOLEAN DEFAULT FALSE
);
SQLEOF
        ok "PostgreSQL schema bootstrapped (titan_mesh)"
        zk_log "POSTGRES_INIT" "schema=titan_mesh"
    else
        warn "PostgreSQL not running — schema will bootstrap on next start"
    fi
}

# ── Kafka Bootstrap (via proot Ubuntu) ───────────────────────────────────────
setup_kafka() {
    step "Setting Up Kafka Message Bus"

    local kafka_dir="$WORKSPACE/kafka"
    mkdir -p "$kafka_dir"

    # Write Kafka startup wrapper (runs inside proot-distro if available)
    cat > "$kafka_dir/start-kafka.sh" << 'KAFKAEOF'
#!/usr/bin/env bash
# Titan Kafka Bootstrap — ARM64 Native
KAFKA_VERSION="3.9.0"
SCALA_VERSION="2.13"
KAFKA_DIR="$HOME/titan-mesh/kafka/kafka_${SCALA_VERSION}-${KAFKA_VERSION}"

if [ ! -d "$KAFKA_DIR" ]; then
    echo "[Kafka] Downloading Kafka ${KAFKA_VERSION}..."
    cd "$HOME/titan-mesh/kafka"
    curl -fL "https://downloads.apache.org/kafka/${KAFKA_VERSION}/kafka_${SCALA_VERSION}-${KAFKA_VERSION}.tgz" \
        -o kafka.tgz
    tar -xzf kafka.tgz
    rm kafka.tgz
    echo "[Kafka] Extracted to $KAFKA_DIR"
fi

cd "$KAFKA_DIR"

# KRaft mode — no Zookeeper needed
if [ ! -f "config/kraft/server.properties.titan" ]; then
    cp config/kraft/server.properties config/kraft/server.properties.titan
    CLUSTER_ID=$(bin/kafka-storage.sh random-uuid)
    echo "[Kafka] Cluster ID: $CLUSTER_ID"
    echo "$CLUSTER_ID" > "$HOME/titan-mesh/kafka/cluster.id"
    bin/kafka-storage.sh format \
        -t "$CLUSTER_ID" \
        -c config/kraft/server.properties
fi

echo "[Kafka] Starting in KRaft mode (no Zookeeper)..."
KAFKA_HEAP_OPTS="-Xmx256m -Xms128m" \
    bin/kafka-server-start.sh config/kraft/server.properties &

sleep 5

# Create Titan mesh topics
bin/kafka-topics.sh --create --if-not-exists \
    --bootstrap-server localhost:9092 \
    --topic titan.audit \
    --partitions 1 --replication-factor 1

bin/kafka-topics.sh --create --if-not-exists \
    --bootstrap-server localhost:9092 \
    --topic titan.mesh.events \
    --partitions 3 --replication-factor 1

bin/kafka-topics.sh --create --if-not-exists \
    --bootstrap-server localhost:9092 \
    --topic titan.zk.ledger \
    --partitions 1 --replication-factor 1

echo "[Kafka] Topics created: titan.audit | titan.mesh.events | titan.zk.ledger"
KAFKAEOF
    chmod +x "$kafka_dir/start-kafka.sh"
    ok "Kafka bootstrap script written to $kafka_dir/start-kafka.sh"
    zk_log "KAFKA_CONFIGURED" "kraft_mode=true topics=titan.audit,titan.mesh.events,titan.zk.ledger"
}

# ── Rust/Tokio API Service ────────────────────────────────────────────────────
write_tokio_service() {
    step "Writing Rust/Tokio Sovereign API Service"

    local svc_dir="$WORKSPACE/titan-tokio-api"
    mkdir -p "$svc_dir/src"

    # Cargo.toml
    cat > "$svc_dir/Cargo.toml" << 'TOMLEOF'
[package]
name = "titan-tokio-api"
version = "2.0.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
axum = { version = "0.7", features = ["json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
hex = "0.4"
rdkafka = { version = "0.36", features = ["cmake-build"] }
sqlx = { version = "0.7", features = ["runtime-tokio-native-tls", "postgres"] }
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4"] }
tower-http = { version = "0.5", features = ["cors", "trace"] }
tracing = "0.1"
tracing-subscriber = "0.3"
TOMLEOF

    # Main service
    cat > "$svc_dir/src/main.rs" << 'RUSTEOF'
//! TitanU Sovereign Mesh API
//! Stack: Axum + Tokio + Kafka Producer + PostgreSQL
//! Patent: JCH-2026-004 (ZK-Audit State Ledger)

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::Utc;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

// ── ZK Audit Entry (JCH-2026-004) ─────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkAuditEntry {
    pub id: String,
    pub ts: String,
    pub device_id: String,
    pub event: String,
    pub payload: serde_json::Value,
    pub hash: String,
    pub chain_hash: String,
}

impl ZkAuditEntry {
    pub fn new(device_id: &str, event: &str, payload: serde_json::Value, prev_hash: &str) -> Self {
        let id = Uuid::new_v4().to_string();
        let ts = Utc::now().to_rfc3339();
        let raw = format!("{}{}{}{}{}", id, ts, device_id, event, payload);
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));
        let chain_input = format!("{}{}", prev_hash, hash);
        let chain_hash = hex::encode(Sha256::digest(chain_input.as_bytes()));
        Self { id, ts, device_id: device_id.to_string(), event: event.to_string(), payload, hash, chain_hash }
    }
}

// ── Mesh Node State ────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNode {
    pub device_id: String,
    pub enrolled_at: String,
    pub last_seen: String,
    pub services: Vec<String>,
    pub status: String,
}

#[derive(Clone)]
pub struct AppState {
    pub device_id: String,
    pub ledger: Arc<RwLock<Vec<ZkAuditEntry>>>,
    pub nodes: Arc<RwLock<Vec<MeshNode>>>,
    pub kafka_producer: Option<Arc<FutureProducer>>,
}

// ── Kafka Producer Init ────────────────────────────────────────────────────
fn init_kafka_producer(brokers: &str) -> Option<Arc<FutureProducer>> {
    ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("message.timeout.ms", "5000")
        .set("queue.buffering.max.ms", "100")
        .create::<FutureProducer>()
        .map(|p| Arc::new(p))
        .map_err(|e| eprintln!("[Kafka] Producer init failed: {e}"))
        .ok()
}

// ── Routes ─────────────────────────────────────────────────────────────────
async fn health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let ledger = state.ledger.read().await;
    Json(serde_json::json!({
        "status": "sovereign",
        "device_id": state.device_id,
        "ts": Utc::now().to_rfc3339(),
        "ledger_entries": ledger.len(),
        "kafka_connected": state.kafka_producer.is_some(),
        "version": "2.0.0-sovereign"
    }))
}

#[derive(Deserialize)]
pub struct AuditRequest {
    pub event: String,
    pub payload: Option<serde_json::Value>,
}

async fn post_audit(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuditRequest>,
) -> Result<Json<ZkAuditEntry>, StatusCode> {
    let mut ledger = state.ledger.write().await;
    let prev_hash = ledger.last().map(|e| e.chain_hash.as_str()).unwrap_or("GENESIS");
    let entry = ZkAuditEntry::new(
        &state.device_id,
        &req.event,
        req.payload.unwrap_or(serde_json::Value::Null),
        prev_hash,
    );

    // Publish to Kafka
    if let Some(ref producer) = state.kafka_producer {
        let payload_str = serde_json::to_string(&entry).unwrap_or_default();
        let record = FutureRecord::to("titan.zk.ledger")
            .payload(&payload_str)
            .key(&entry.device_id);
        let _ = producer.send(record, Duration::from_secs(5)).await;
    }

    ledger.push(entry.clone());
    Ok(Json(entry))
}

async fn get_ledger(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let ledger = state.ledger.read().await;
    Json(serde_json::json!({
        "device_id": state.device_id,
        "count": ledger.len(),
        "entries": *ledger
    }))
}

#[derive(Deserialize)]
pub struct EnrollRequest {
    pub device_id: String,
    pub services: Vec<String>,
    pub mesh_version: String,
}

async fn enroll_node(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollRequest>,
) -> Json<serde_json::Value> {
    let node = MeshNode {
        device_id: req.device_id.clone(),
        enrolled_at: Utc::now().to_rfc3339(),
        last_seen: Utc::now().to_rfc3339(),
        services: req.services.clone(),
        status: "active".to_string(),
    };

    let mut nodes = state.nodes.write().await;
    nodes.retain(|n| n.device_id != req.device_id);
    nodes.push(node.clone());

    if let Some(ref producer) = state.kafka_producer {
        let payload_str = serde_json::to_string(&node).unwrap_or_default();
        let record = FutureRecord::to("titan.mesh.events")
            .payload(&payload_str)
            .key(&req.device_id);
        let _ = producer.send(record, Duration::from_secs(5)).await;
    }

    Json(serde_json::json!({
        "enrolled": true,
        "device_id": req.device_id,
        "ts": Utc::now().to_rfc3339()
    }))
}

async fn list_nodes(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let nodes = state.nodes.read().await;
    Json(serde_json::json!({ "nodes": *nodes, "count": nodes.len() }))
}

// ── Main ───────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let device_id = std::env::var("TITAN_DEVICE_ID")
        .unwrap_or_else(|_| "TITAN-LOCAL".to_string());
    let kafka_brokers = std::env::var("KAFKA_BROKERS")
        .unwrap_or_else(|_| "127.0.0.1:9092".to_string());
    let port = std::env::var("TOKIO_PORT")
        .unwrap_or_else(|_| "8080".to_string());

    let kafka_producer = init_kafka_producer(&kafka_brokers);
    if kafka_producer.is_some() {
        println!("[Kafka] Producer connected to {kafka_brokers}");
    } else {
        println!("[Kafka] Running without Kafka (offline sovereign mode)");
    }

    let state = Arc::new(AppState {
        device_id: device_id.clone(),
        ledger: Arc::new(RwLock::new(Vec::new())),
        nodes: Arc::new(RwLock::new(Vec::new())),
        kafka_producer,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/audit", post(post_audit))
        .route("/audit/ledger", get(get_ledger))
        .route("/mesh/enroll", post(enroll_node))
        .route("/mesh/nodes", get(list_nodes))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    println!("[TitanU] Sovereign Tokio API running on http://{addr}");
    println!("[TitanU] Device: {device_id}");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
RUSTEOF

    # Build script
    cat > "$svc_dir/build.sh" << 'BUILDEOF'
#!/usr/bin/env bash
cd "$(dirname "$0")"
echo "[Rust] Building titan-tokio-api (release)..."
cargo build --release 2>&1
echo "[Rust] Binary: ./target/release/titan-tokio-api"
BUILDEOF
    chmod +x "$svc_dir/build.sh"

    ok "Rust/Tokio service written to $svc_dir"
    zk_log "TOKIO_SERVICE_WRITTEN" "path=$svc_dir"
}

# ── Kotlin/Ktor Service ───────────────────────────────────────────────────────
write_kotlin_service() {
    step "Writing Kotlin/Ktor Mesh Gateway"

    local svc_dir="$WORKSPACE/titan-ktor-gateway"
    mkdir -p "$svc_dir/src/main/kotlin/titanu"

    # build.gradle.kts
    cat > "$svc_dir/build.gradle.kts" << 'GRADLEEOF'
plugins {
    kotlin("jvm") version "2.0.0"
    kotlin("plugin.serialization") version "2.0.0"
    id("io.ktor.plugin") version "2.3.12"
    application
}

group = "ai.titanu"
version = "2.0.0-sovereign"

application {
    mainClass.set("titanu.ApplicationKt")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.ktor:ktor-server-core-jvm")
    implementation("io.ktor:ktor-server-netty-jvm")
    implementation("io.ktor:ktor-server-content-negotiation-jvm")
    implementation("io.ktor:ktor-serialization-kotlinx-json-jvm")
    implementation("io.ktor:ktor-server-cors-jvm")
    implementation("io.ktor:ktor-server-call-logging-jvm")
    implementation("io.ktor:ktor-client-core-jvm")
    implementation("io.ktor:ktor-client-cio-jvm")
    implementation("io.ktor:ktor-client-content-negotiation-jvm")
    implementation("org.apache.kafka:kafka-clients:3.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("ch.qos.logback:logback-classic:1.5.6")
}

ktor {
    fatJar {
        archiveFileName.set("titan-ktor-gateway.jar")
    }
}
GRADLEEOF

    # Main Application
    cat > "$svc_dir/src/main/kotlin/titanu/Application.kt" << 'KOTLINEOF'
package titanu

/**
 * TitanU Sovereign Mesh — Kotlin/Ktor Gateway
 * Routes: mesh enrollment, Kafka event relay, ZK audit proxy
 * Connects: Tokio API (Rust) + Kafka + Julia analytics
 */

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.routing.*
import io.ktor.server.response.*
import io.ktor.server.request.*
import io.ktor.http.*
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import org.apache.kafka.clients.producer.*
import org.apache.kafka.common.serialization.StringSerializer
import java.security.MessageDigest
import java.time.Instant
import java.util.*
import java.util.concurrent.ConcurrentLinkedQueue

// ── Data Models ──────────────────────────────────────────────────────────────
@Serializable
data class MeshEvent(
    val id: String = UUID.randomUUID().toString(),
    val ts: String = Instant.now().toString(),
    val deviceId: String,
    val eventType: String,
    val payload: JsonElement = JsonNull,
    val hash: String = ""
)

@Serializable
data class GatewayHealth(
    val status: String = "sovereign",
    val service: String = "titan-ktor-gateway",
    val version: String = "2.0.0-sovereign",
    val ts: String = Instant.now().toString(),
    val kafkaConnected: Boolean,
    val tokioApiReachable: Boolean,
    val juliaApiReachable: Boolean,
    val queueDepth: Int
)

@Serializable
data class EnrollRequest(val deviceId: String, val services: List<String>)

// ── Kafka Producer ────────────────────────────────────────────────────────────
object KafkaRelay {
    private val producer: KafkaProducer<String, String>? by lazy {
        try {
            val props = Properties().apply {
                put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,
                    System.getenv("KAFKA_BROKERS") ?: "127.0.0.1:9092")
                put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
                put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
                put(ProducerConfig.ACKS_CONFIG, "1")
                put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, "5000")
                put(ProducerConfig.MAX_BLOCK_MS_CONFIG, "3000")
            }
            KafkaProducer(props)
        } catch (e: Exception) {
            println("[Kafka] Producer unavailable: ${e.message}")
            null
        }
    }

    val connected: Boolean get() = producer != null

    fun publish(topic: String, key: String, value: String) {
        producer?.send(ProducerRecord(topic, key, value))
    }
}

// ── ZK Hash ───────────────────────────────────────────────────────────────────
fun zkHash(input: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(input.toByteArray()).joinToString("") { "%02x".format(it) }
}

// ── Event Queue (offline buffer) ──────────────────────────────────────────────
val eventQueue = ConcurrentLinkedQueue<MeshEvent>()

fun main() {
    val port = System.getenv("KOTLIN_PORT")?.toIntOrNull() ?: 8081
    val tokioUrl = System.getenv("TOKIO_API_URL") ?: "http://127.0.0.1:8080"
    val juliaUrl = System.getenv("JULIA_API_URL") ?: "http://127.0.0.1:8082"
    val deviceId = System.getenv("TITAN_DEVICE_ID") ?: "TITAN-LOCAL"

    val httpClient = HttpClient(CIO) {
        install(ClientContentNegotiation) { json() }
        engine { requestTimeout = 5000 }
    }

    println("[TitanU] Ktor Gateway starting on port $port")
    println("[TitanU] Tokio upstream: $tokioUrl")
    println("[TitanU] Julia upstream: $juliaUrl")

    embeddedServer(Netty, port = port, host = "0.0.0.0") {
        install(ContentNegotiation) { json(Json { prettyPrint = true; isLenient = true }) }
        install(CORS) {
            anyHost()
            allowHeader(HttpHeaders.ContentType)
            allowHeader(HttpHeaders.Authorization)
            allowMethod(HttpMethod.Get)
            allowMethod(HttpMethod.Post)
        }

        routing {
            // ── Health ────────────────────────────────────────────────────────
            get("/health") {
                var tokioOk = false
                var juliaOk = false
                try { httpClient.get("$tokioUrl/health"); tokioOk = true } catch (_: Exception) {}
                try { httpClient.get("$juliaUrl/health"); juliaOk = true } catch (_: Exception) {}

                call.respond(GatewayHealth(
                    kafkaConnected = KafkaRelay.connected,
                    tokioApiReachable = tokioOk,
                    juliaApiReachable = juliaOk,
                    queueDepth = eventQueue.size
                ))
            }

            // ── Mesh Enrollment Relay ─────────────────────────────────────────
            post("/mesh/enroll") {
                val req = call.receive<EnrollRequest>()
                val event = MeshEvent(
                    deviceId = req.deviceId,
                    eventType = "MESH_ENROLL",
                    payload = Json.encodeToJsonElement(req),
                    hash = zkHash("${req.deviceId}MESH_ENROLL${Instant.now()}")
                )

                KafkaRelay.publish(
                    "titan.mesh.events",
                    req.deviceId,
                    Json.encodeToString(event)
                )
                eventQueue.add(event)

                // Forward to Tokio API
                try {
                    val resp = httpClient.post("$tokioUrl/mesh/enroll") {
                        contentType(ContentType.Application.Json)
                        setBody(req)
                    }
                    call.respondText(resp.bodyAsText(), ContentType.Application.Json)
                } catch (e: Exception) {
                    call.respond(HttpStatusCode.Accepted, mapOf(
                        "queued" to true,
                        "event_id" to event.id,
                        "note" to "Tokio API offline — event buffered"
                    ))
                }
            }

            // ── Event Relay ───────────────────────────────────────────────────
            post("/events/relay") {
                val body = call.receiveText()
                val hash = zkHash(body)
                KafkaRelay.publish("titan.mesh.events", deviceId, body)
                call.respond(mapOf("relayed" to true, "hash" to hash))
            }

            // ── ZK Audit Proxy ────────────────────────────────────────────────
            post("/audit") {
                val body = call.receiveText()
                val hash = zkHash("$deviceId$body${Instant.now()}")
                KafkaRelay.publish("titan.zk.ledger", deviceId, body)
                try {
                    val resp = httpClient.post("$tokioUrl/audit") {
                        contentType(ContentType.Application.Json)
                        setBody(body)
                    }
                    call.respondText(resp.bodyAsText(), ContentType.Application.Json)
                } catch (e: Exception) {
                    call.respond(HttpStatusCode.Accepted, mapOf(
                        "buffered" to true,
                        "hash" to hash
                    ))
                }
            }

            // ── Julia Analytics Proxy ─────────────────────────────────────────
            get("/analytics/{path...}") {
                val path = call.parameters.getAll("path")?.joinToString("/") ?: ""
                try {
                    val resp = httpClient.get("$juliaUrl/$path")
                    call.respondText(resp.bodyAsText(), ContentType.Application.Json)
                } catch (e: Exception) {
                    call.respond(HttpStatusCode.ServiceUnavailable,
                        mapOf("error" to "Julia analytics offline", "path" to path))
                }
            }

            // ── Queue Drain ───────────────────────────────────────────────────
            get("/queue/status") {
                call.respond(mapOf(
                    "depth" to eventQueue.size,
                    "kafka_connected" to KafkaRelay.connected
                ))
            }
        }
    }.start(wait = true)
}
KOTLINEOF

    # Gradle wrapper bootstrap
    cat > "$svc_dir/gradlew_bootstrap.sh" << 'GRADLEWEOF'
#!/usr/bin/env bash
# Bootstrap Gradle wrapper for Termux (requires JDK)
cd "$(dirname "$0")"
if ! command -v gradle &>/dev/null && ! command -v java &>/dev/null; then
    echo "[Kotlin] JDK required. In Termux: pkg install openjdk-21"
    exit 1
fi
if [ ! -f "gradlew" ]; then
    gradle wrapper --gradle-version=8.8 2>/dev/null || \
    echo "[Kotlin] Run 'gradle wrapper' manually after installing gradle"
fi
echo "[Kotlin] Build with: ./gradlew buildFatJar"
echo "[Kotlin] Run with:   java -jar build/libs/titan-ktor-gateway.jar"
GRADLEWEOF
    chmod +x "$svc_dir/gradlew_bootstrap.sh"

    ok "Kotlin/Ktor gateway written to $svc_dir"
    zk_log "KOTLIN_SERVICE_WRITTEN" "path=$svc_dir"
}

# ── Julia Analytics Service ───────────────────────────────────────────────────
write_julia_service() {
    step "Writing Julia Sovereign Analytics Service"

    local svc_dir="$WORKSPACE/titan-julia-analytics"
    mkdir -p "$svc_dir"

    cat > "$svc_dir/server.jl" << 'JULIAEOF'
# ==============================================================================
# TitanU Sovereign Analytics — Julia HTTP Service
# Stack: HTTP.jl + JSON3.jl + Kafka consumer bridge
# Provides: mesh telemetry, ZK ledger analytics, node health scoring
# ==============================================================================

using Pkg

# Auto-install dependencies
for pkg in ["HTTP", "JSON3", "Dates", "Statistics", "SHA", "UUIDs"]
    try
        eval(Meta.parse("using $pkg"))
    catch
        Pkg.add(pkg)
        eval(Meta.parse("using $pkg"))
    end
end

using HTTP, JSON3, Dates, Statistics, SHA, UUIDs

const PORT = parse(Int, get(ENV, "JULIA_PORT", "8082"))
const DEVICE_ID = get(ENV, "TITAN_DEVICE_ID", "TITAN-LOCAL")
const KAFKA_BROKERS = get(ENV, "KAFKA_BROKERS", "127.0.0.1:9092")

# ── In-memory telemetry store ─────────────────────────────────────────────────
const telemetry_store = Dict{String, Vector{Dict}}()
const node_scores = Dict{String, Float64}()
const audit_chain = Vector{Dict}()

# ── ZK Hash ───────────────────────────────────────────────────────────────────
function zk_hash(data::String)::String
    bytes2hex(sha256(data))
end

# ── Node Health Scoring ───────────────────────────────────────────────────────
function score_node(node_id::String, events::Vector{Dict})::Float64
    isempty(events) && return 0.0
    recent = filter(e -> haskey(e, "ts"), events)
    event_count = length(events)
    error_count = count(e -> get(e, "status", "") == "error", events)
    uptime_score = min(event_count / 100.0, 1.0) * 40.0
    error_penalty = min(error_count / max(event_count, 1) * 30.0, 30.0)
    base_score = 60.0
    score = base_score + uptime_score - error_penalty
    clamp(score, 0.0, 100.0)
end

# ── Analytics Computation ─────────────────────────────────────────────────────
function compute_mesh_analytics()
    total_nodes = length(keys(telemetry_store))
    total_events = sum(length(v) for v in values(telemetry_store); init=0)
    scores = collect(values(node_scores))
    avg_score = isempty(scores) ? 0.0 : mean(scores)
    chain_integrity = length(audit_chain)

    Dict(
        "timestamp" => string(now(UTC)),
        "device_id" => DEVICE_ID,
        "mesh_analytics" => Dict(
            "total_nodes" => total_nodes,
            "total_events" => total_events,
            "avg_health_score" => round(avg_score, digits=2),
            "audit_chain_depth" => chain_integrity,
            "sovereignty_index" => min(total_nodes * 0.1 + avg_score * 0.9, 100.0)
        ),
        "node_scores" => node_scores,
        "zk_chain_tip" => isempty(audit_chain) ? "GENESIS" :
            get(last(audit_chain), "chain_hash", "unknown")
    )
end

# ── Router ────────────────────────────────────────────────────────────────────
function router(req::HTTP.Request)
    path = req.target
    method = req.method

    # Health
    path == "/health" && return HTTP.Response(200, ["Content-Type" => "application/json"],
        JSON3.write(Dict(
            "status" => "sovereign",
            "service" => "titan-julia-analytics",
            "version" => "2.0.0-sovereign",
            "ts" => string(now(UTC)),
            "nodes_tracked" => length(keys(telemetry_store)),
            "audit_depth" => length(audit_chain)
        )))

    # Mesh analytics
    path == "/analytics/mesh" && method == "GET" &&
        return HTTP.Response(200, ["Content-Type" => "application/json"],
            JSON3.write(compute_mesh_analytics()))

    # Ingest telemetry event
    if path == "/telemetry" && method == "POST"
        body = String(req.body)
        event = try JSON3.read(body, Dict) catch; Dict() end
        node_id = get(event, "device_id", "unknown")

        if !haskey(telemetry_store, node_id)
            telemetry_store[node_id] = []
        end
        push!(telemetry_store[node_id], Dict(event))
        node_scores[node_id] = score_node(node_id, telemetry_store[node_id])

        # ZK chain entry
        ts = string(now(UTC))
        prev_hash = isempty(audit_chain) ? "GENESIS" :
            get(last(audit_chain), "chain_hash", "GENESIS")
        entry_raw = "$(node_id)$(ts)$(body)"
        h = zk_hash(entry_raw)
        chain_hash = zk_hash("$(prev_hash)$(h)")
        push!(audit_chain, Dict("ts" => ts, "node_id" => node_id,
            "hash" => h, "chain_hash" => chain_hash))

        return HTTP.Response(200, ["Content-Type" => "application/json"],
            JSON3.write(Dict(
                "ingested" => true,
                "node_id" => node_id,
                "health_score" => node_scores[node_id],
                "chain_hash" => chain_hash
            )))
    end

    # Node score
    if startswith(path, "/analytics/node/")
        node_id = split(path, "/")[end]
        score = get(node_scores, node_id, -1.0)
        score == -1.0 &&
            return HTTP.Response(404, ["Content-Type" => "application/json"],
                JSON3.write(Dict("error" => "node not found", "node_id" => node_id)))
        return HTTP.Response(200, ["Content-Type" => "application/json"],
            JSON3.write(Dict(
                "node_id" => node_id,
                "health_score" => score,
                "event_count" => length(get(telemetry_store, node_id, [])),
                "ts" => string(now(UTC))
            )))
    end

    # ZK chain
    path == "/audit/chain" && return HTTP.Response(200,
        ["Content-Type" => "application/json"],
        JSON3.write(Dict(
            "depth" => length(audit_chain),
            "tip" => isempty(audit_chain) ? "GENESIS" : last(audit_chain),
            "chain" => last(audit_chain, min(10, length(audit_chain)))
        )))

    HTTP.Response(404, ["Content-Type" => "application/json"],
        JSON3.write(Dict("error" => "not found", "path" => path)))
end

# ── Start Server ──────────────────────────────────────────────────────────────
println("[Julia] TitanU Analytics Service starting on port $PORT")
println("[Julia] Device: $DEVICE_ID")
println("[Julia] Endpoints: /health /analytics/mesh /telemetry /analytics/node/:id /audit/chain")

HTTP.serve(router, "0.0.0.0", PORT)
JULIAEOF

    # Install script
    cat > "$svc_dir/install_julia.sh" << 'JLINSTEOF'
#!/usr/bin/env bash
# Install Julia in Termux via proot-distro Ubuntu
set -e
if command -v julia &>/dev/null; then
    echo "[Julia] Already installed: $(julia --version)"
    exit 0
fi

JULIA_VERSION="1.10.4"
ARCH=$(uname -m)
echo "[Julia] Installing Julia $JULIA_VERSION for $ARCH..."

if [ "$ARCH" = "aarch64" ]; then
    URL="https://julialang-s3.julialang.org/bin/linux/aarch64/1.10/julia-${JULIA_VERSION}-linux-aarch64.tar.gz"
else
    URL="https://julialang-s3.julialang.org/bin/linux/x86_64/1.10/julia-${JULIA_VERSION}-linux-x86_64.tar.gz"
fi

cd "$HOME"
curl -fL "$URL" -o julia.tar.gz
tar -xzf julia.tar.gz
rm julia.tar.gz
ln -sf "$HOME/julia-${JULIA_VERSION}/bin/julia" "$PREFIX/bin/julia"
echo "[Julia] Installed: $(julia --version)"
JLINSTEOF
    chmod +x "$svc_dir/install_julia.sh"

    ok "Julia analytics service written to $svc_dir"
    zk_log "JULIA_SERVICE_WRITTEN" "path=$svc_dir"
}

# ── Process Supervisor (start all services) ───────────────────────────────────
write_supervisor() {
    step "Writing Titan Mesh Process Supervisor"

    cat > "$WORKSPACE/titan-start.sh" << SUPEOF
#!/usr/bin/env bash
# ==============================================================================
# TITAN SOVEREIGN MESH — Master Start Script
# Starts: PostgreSQL → Kafka → Tokio API → Ktor Gateway → Julia Analytics
# ==============================================================================
set -uo pipefail

WORKSPACE="\$HOME/titan-mesh"
KEYS_DIR="\$WORKSPACE/.keys"
LOGS_DIR="\$WORKSPACE/logs"
mkdir -p "\$LOGS_DIR"

# Load device identity
export TITAN_DEVICE_ID=\$(cat "\$KEYS_DIR/device.id" 2>/dev/null || echo "TITAN-UNBOUND")
export KAFKA_BROKERS="127.0.0.1:${KAFKA_PORT}"
export TOKIO_PORT="${TOKIO_API_PORT}"
export KOTLIN_PORT="${KOTLIN_PORT}"
export JULIA_PORT="${JULIA_PORT}"
export TOKIO_API_URL="http://127.0.0.1:${TOKIO_API_PORT}"
export JULIA_API_URL="http://127.0.0.1:${JULIA_PORT}"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║  TITAN SOVEREIGN MESH - BOOT SEQUENCE ║"
echo "  ║  Device: \$TITAN_DEVICE_ID            ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# 1. PostgreSQL
echo "[1/5] Starting PostgreSQL..."
PG_DATA="\$WORKSPACE/pgdata"
if [ -d "\$PG_DATA" ] && command -v pg_ctl &>/dev/null; then
    pg_ctl status -D "\$PG_DATA" &>/dev/null || \
        pg_ctl start -D "\$PG_DATA" -l "\$LOGS_DIR/postgres.log" \
        -o "-p ${POSTGRES_PORT}" &>/dev/null
    echo "  [✓] PostgreSQL on :${POSTGRES_PORT}"
else
    echo "  [!] PostgreSQL not configured — run the setup script first"
fi

# 2. Kafka
echo "[2/5] Starting Kafka..."
KAFKA_SCRIPT="\$WORKSPACE/kafka/start-kafka.sh"
if [ -f "\$KAFKA_SCRIPT" ]; then
    bash "\$KAFKA_SCRIPT" >> "\$LOGS_DIR/kafka.log" 2>&1 &
    echo "  [✓] Kafka starting on :${KAFKA_PORT} (log: \$LOGS_DIR/kafka.log)"
else
    echo "  [!] Kafka not configured"
fi

sleep 3

# 3. Rust/Tokio API
echo "[3/5] Starting Rust/Tokio API..."
TOKIO_BIN="\$WORKSPACE/titan-tokio-api/target/release/titan-tokio-api"
if [ -f "\$TOKIO_BIN" ]; then
    "\$TOKIO_BIN" >> "\$LOGS_DIR/tokio.log" 2>&1 &
    echo "  [✓] Tokio API on :${TOKIO_API_PORT} (log: \$LOGS_DIR/tokio.log)"
else
    echo "  [!] Tokio binary not built — cd titan-tokio-api && cargo build --release"
fi

# 4. Kotlin/Ktor Gateway
echo "[4/5] Starting Kotlin/Ktor Gateway..."
KTOR_JAR="\$WORKSPACE/titan-ktor-gateway/build/libs/titan-ktor-gateway.jar"
if [ -f "\$KTOR_JAR" ] && command -v java &>/dev/null; then
    java -Xmx128m -jar "\$KTOR_JAR" >> "\$LOGS_DIR/ktor.log" 2>&1 &
    echo "  [✓] Ktor Gateway on :${KOTLIN_PORT} (log: \$LOGS_DIR/ktor.log)"
else
    echo "  [!] Ktor JAR not built — cd titan-ktor-gateway && ./gradlew buildFatJar"
fi

# 5. Julia Analytics
echo "[5/5] Starting Julia Analytics..."
JULIA_SVC="\$WORKSPACE/titan-julia-analytics/server.jl"
if command -v julia &>/dev/null && [ -f "\$JULIA_SVC" ]; then
    julia "\$JULIA_SVC" >> "\$LOGS_DIR/julia.log" 2>&1 &
    echo "  [✓] Julia Analytics on :${JULIA_PORT} (log: \$LOGS_DIR/julia.log)"
else
    echo "  [!] Julia not installed — run: \$WORKSPACE/titan-julia-analytics/install_julia.sh"
fi

echo ""
echo "  ┌─────────────────────────────────────┐"
echo "  │  TITAN MESH SERVICES                │"
echo "  │  Postgres  → :${POSTGRES_PORT}                  │"
echo "  │  Kafka     → :${KAFKA_PORT}                  │"
echo "  │  Tokio API → :${TOKIO_API_PORT}                  │"
echo "  │  Ktor GW   → :${KOTLIN_PORT}                  │"
echo "  │  Julia     → :${JULIA_PORT}                  │"
echo "  └─────────────────────────────────────┘"
echo ""
echo "  Health check: curl http://127.0.0.1:${TOKIO_API_PORT}/health"
echo "  Ktor health:  curl http://127.0.0.1:${KOTLIN_PORT}/health"
echo "  Julia mesh:   curl http://127.0.0.1:${JULIA_PORT}/analytics/mesh"
echo ""
SUPEOF
    chmod +x "$WORKSPACE/titan-start.sh"

    # Stop script
    cat > "$WORKSPACE/titan-stop.sh" << 'STOPEOF'
#!/usr/bin/env bash
echo "[TitanU] Stopping all mesh services..."
pkill -f "titan-tokio-api" 2>/dev/null && echo "  [✓] Tokio API stopped" || true
pkill -f "titan-ktor-gateway" 2>/dev/null && echo "  [✓] Ktor Gateway stopped" || true
pkill -f "titan-julia-analytics/server.jl" 2>/dev/null && echo "  [✓] Julia stopped" || true
pkill -f "kafka-server-start" 2>/dev/null && echo "  [✓] Kafka stopped" || true
PG_DATA="$HOME/titan-mesh/pgdata"
[ -d "$PG_DATA" ] && command -v pg_ctl &>/dev/null && \
    pg_ctl stop -D "$PG_DATA" -m fast 2>/dev/null && echo "  [✓] PostgreSQL stopped" || true
echo "[TitanU] Mesh offline."
STOPEOF
    chmod +x "$WORKSPACE/titan-stop.sh"

    ok "Supervisor scripts: titan-start.sh | titan-stop.sh"
    zk_log "SUPERVISOR_WRITTEN" "workspace=$WORKSPACE"
}

# ── Updated moat CLI (with ZK chain) ─────────────────────────────────────────
write_moat_v2() {
    step "Writing moat v2 (ZK Chain Edition)"

    cat > "$PREFIX/bin/moat" << 'MOATEOF'
#!/usr/bin/env bash
# JU MOAT v2.0 - Sovereign Perimeter CLI + ZK Audit Chain
# Patent: JCH-2026-004 (ZK-Audit State Ledger)
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
NC='\033[0m'; BOLD='\033[1m'

MOAT_VERSION="2.0.0-sovereign"
LOG_FILE="$HOME/.moat_audit.log"
ZK_CHAIN_FILE="$HOME/.moat_zk_chain.log"
WORKSPACE="$HOME/titan-mesh"
LOCK_MODE="${MOAT_LOCK_MODE:-600}"
DRY_RUN=0
SKIP_PATTERNS=(".git" "node_modules" "__pycache__" "target")
DEVICE_ID=$(cat "$WORKSPACE/.keys/device.id" 2>/dev/null || echo "TITAN-UNBOUND")
TOKIO_API="http://127.0.0.1:8080"

declare -i C_LOCKED=0 C_SKIPPED_SYMLINK=0 C_SKIPPED_EXCLUDE=0 C_ERRORS=0

# ZK Chain: each lock event hashes into the previous
zk_chain_entry() {
    local event="$1" payload="$2"
    local ts; ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local prev_hash
    prev_hash=$(tail -1 "$ZK_CHAIN_FILE" 2>/dev/null | awk '{print $NF}' | \
        sed 's/chain_hash=//' || echo "GENESIS")
    local raw="${DEVICE_ID}${ts}${event}${payload}"
    local hash; hash=$(echo "$raw" | sha256sum | awk '{print $1}')
    local chain_raw="${prev_hash}${hash}"
    local chain_hash; chain_hash=$(echo "$chain_raw" | sha256sum | awk '{print $1}')
    echo "ts=${ts} device=${DEVICE_ID} event=${event} payload=${payload} hash=${hash} chain_hash=${chain_hash}" \
        >> "$ZK_CHAIN_FILE"

    # Publish to Tokio API if reachable
    curl -sf --max-time 2 -X POST "$TOKIO_API/audit" \
        -H "Content-Type: application/json" \
        -d "{\"event\":\"${event}\",\"payload\":{\"detail\":\"${payload}\",\"chain_hash\":\"${chain_hash}\"}}" \
        &>/dev/null || true

    echo -e "  ${MAGENTA}[ZK-CHAIN]${NC} ${event} → ${chain_hash:0:20}..."
}

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ███╗   ███╗ ██████╗  █████╗ ████████╗  v${MOAT_VERSION}"
    echo "  ████╗ ████║██╔═══██╗██╔══██╗╚══██╔══╝"
    echo "  ██╔████╔██║██║   ██║███████║   ██║   "
    echo "  ██║╚██╔╝██║██║   ██║██╔══██║   ██║   "
    echo "  ██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║   "
    echo "  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   "
    echo "  [ Sovereign Perimeter + ZK Audit Chain ]"
    echo -e "${NC}"
}

should_skip() {
    local path="$1"; local base; base=$(basename "$path")
    for pattern in "${SKIP_PATTERNS[@]}"; do [ "$base" = "$pattern" ] && return 0; done
    return 1
}

recursive_shield() {
    local target_dir="$1"
    [ ! -d "$target_dir" ] && { echo -e "${RED}[!] Not a directory: $target_dir${NC}"; return 1; }

    while IFS= read -r -d '' item; do
        if should_skip "$item"; then
            echo -e "  ${YELLOW}[SKIP-EXCLUDE]${NC} $item"; ((C_SKIPPED_EXCLUDE++)); continue
        fi
        if [ -L "$item" ]; then
            echo -e "  ${YELLOW}[SKIP-SYMLINK]${NC} $item"; ((C_SKIPPED_SYMLINK++)); continue
        fi
        if [ "$DRY_RUN" -eq 1 ]; then
            echo -e "  ${CYAN}[DRY-RUN]${NC} Would lock: $item"; ((C_LOCKED++)); continue
        fi

        local file_hash
        if file_hash=$(sha256sum "$item" 2>/dev/null | awk '{print $1}'); then
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] LOCKED: $item | HASH: $file_hash | MODE: $LOCK_MODE" \
                >> "$LOG_FILE"
            if chmod "$LOCK_MODE" "$item" 2>/dev/null; then
                zk_chain_entry "FILE_LOCKED" "$(basename "$item"):$file_hash"
                echo -e "  ${BLUE}[⚡ SHIELDING]${NC} $(basename "$item")"
                ((C_LOCKED++))
            else
                echo -e "  ${RED}[ERR]${NC} chmod failed: $item"; ((C_ERRORS++))
            fi
        else
            echo -e "  ${RED}[ERR]${NC} hash failed: $item"; ((C_ERRORS++))
        fi
    done < <(find "$target_dir" -type f -print0 2>/dev/null)
}

cmd_shield() {
    local target=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run) DRY_RUN=1 ;;
            --mode) shift; LOCK_MODE="${1:-600}" ;;
            *) [ -z "$target" ] && target="$1" ;;
        esac; shift
    done
    [ -z "$target" ] && { echo -e "${RED}[!] Specify a target directory${NC}"; exit 1; }
    ! command -v sha256sum &>/dev/null && { echo -e "${RED}[!] sha256sum not found${NC}"; exit 1; }

    banner
    echo -e "${CYAN}[*] Moat Shield on:${NC} $target"
    [ "$DRY_RUN" -eq 1 ] && echo -e "${YELLOW}[*] DRY RUN${NC}"
    echo -e "${BLUE}[*] Mode: $LOCK_MODE | ZK Chain: $ZK_CHAIN_FILE${NC}\n"
    zk_chain_entry "SHIELD_START" "$target"
    recursive_shield "$target"
    zk_chain_entry "SHIELD_COMPLETE" "locked=${C_LOCKED} errors=${C_ERRORS}"
    echo ""
    echo -e "${GREEN}${BOLD}✔ Done.${NC}"
    echo -e "  Locked: ${GREEN}$C_LOCKED${NC}  Symlinks: ${YELLOW}$C_SKIPPED_SYMLINK${NC}  Excluded: ${YELLOW}$C_SKIPPED_EXCLUDE${NC}  Errors: ${RED}$C_ERRORS${NC}"
}

cmd_status() {
    banner
    echo -e "${BOLD}Sovereign Mesh Status:${NC}"
    echo "────────────────────────────────────────"
    echo -e "Device ID     : $DEVICE_ID"
    echo -e "Audit Log     : $LOG_FILE ($(wc -l < "$LOG_FILE" 2>/dev/null || echo 0) entries)"
    echo -e "ZK Chain      : $ZK_CHAIN_FILE ($(wc -l < "$ZK_CHAIN_FILE" 2>/dev/null || echo 0) blocks)"
    echo -e "ZK Chain Tip  : $(tail -1 "$ZK_CHAIN_FILE" 2>/dev/null | grep -o 'chain_hash=[a-f0-9]*' | head -c 32 || echo 'GENESIS')"
    echo ""
    echo -e "${BOLD}Service Health:${NC}"
    for svc_port in "Tokio API:8080" "Ktor Gateway:8081" "Julia Analytics:8082"; do
        name="${svc_port%%:*}"; port="${svc_port##*:}"
        if curl -sf --max-time 2 "http://127.0.0.1:$port/health" &>/dev/null; then
            echo -e "  ${GREEN}[✓]${NC} $name (:$port)"
        else
            echo -e "  ${RED}[✗]${NC} $name (:$port) — offline"
        fi
    done
    echo "────────────────────────────────────────"
}

cmd_chain() {
    echo -e "${MAGENTA}${BOLD}ZK Audit Chain (last 10 blocks):${NC}"
    echo "────────────────────────────────────────"
    tail -10 "$ZK_CHAIN_FILE" 2>/dev/null | while IFS= read -r line; do
        ts=$(echo "$line" | grep -o 'ts=[^ ]*' | head -1)
        event=$(echo "$line" | grep -o 'event=[^ ]*' | head -1)
        chain=$(echo "$line" | grep -o 'chain_hash=[a-f0-9]*')
        echo -e "  ${CYAN}${ts}${NC} ${YELLOW}${event}${NC} → ${MAGENTA}${chain:0:30}...${NC}"
    done
    echo "────────────────────────────────────────"
    echo -e "Total blocks: $(wc -l < "$ZK_CHAIN_FILE" 2>/dev/null || echo 0)"
}

case "${1:-}" in
    init)   banner; echo -e "${GREEN}[✓] Moat v${MOAT_VERSION} initialized. Device: $DEVICE_ID${NC}" ;;
    shield) shift; cmd_shield "$@" ;;
    status) cmd_status ;;
    chain)  cmd_chain ;;
    version) echo "JU MOAT v${MOAT_VERSION} | Device: $DEVICE_ID" ;;
    *) banner
       echo -e "${BOLD}Commands:${NC}"
       echo -e "  ${GREEN}init${NC}              Initialize and display status"
       echo -e "  ${GREEN}shield <dir>${NC}      ZK-chain recursive file lock"
       echo -e "  ${GREEN}status${NC}            Mesh + service health"
       echo -e "  ${GREEN}chain${NC}             View ZK audit chain"
       echo -e "  ${GREEN}version${NC}           Build info"
       echo ""
       echo -e "${BOLD}Options:${NC}"
       echo -e "  ${YELLOW}--dry-run${NC}         Preview without changes"
       echo -e "  ${YELLOW}--mode <octal>${NC}    Permission mode (default: 600)"
       ;;
esac
MOATEOF
    chmod +x "$PREFIX/bin/moat"
    ok "moat v2 installed to $PREFIX/bin/moat"
    zk_log "MOAT_V2_INSTALLED" "version=2.0.0-sovereign"
}

# ── Final Summary ─────────────────────────────────────────────────────────────
print_summary() {
    local device_id
    device_id=$(cat "$KEYS_DIR/device.id" 2>/dev/null || echo "UNBOUND")

    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║    TITAN SOVEREIGN MESH — SETUP COMPLETE     ║"
    echo "  ╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${CYAN}Device ID  :${NC} $device_id"
    echo -e "  ${CYAN}Workspace  :${NC} $WORKSPACE"
    echo -e "  ${CYAN}ZK Log     :${NC} $LOG_FILE"
    echo -e "  ${CYAN}ZK Chain   :${NC} $HOME/.moat_zk_chain.log"
    echo ""
    echo -e "  ${BOLD}Services Written:${NC}"
    echo -e "  ${GREEN}✓${NC} Rust/Tokio API   → $WORKSPACE/titan-tokio-api"
    echo -e "  ${GREEN}✓${NC} Kotlin/Ktor GW   → $WORKSPACE/titan-ktor-gateway"
    echo -e "  ${GREEN}✓${NC} Julia Analytics  → $WORKSPACE/titan-julia-analytics"
    echo -e "  ${GREEN}✓${NC} Kafka Bootstrap  → $WORKSPACE/kafka/start-kafka.sh"
    echo -e "  ${GREEN}✓${NC} PostgreSQL       → $WORKSPACE/pgdata"
    echo -e "  ${GREEN}✓${NC} moat v2 CLI      → $PREFIX/bin/moat"
    echo ""
    echo -e "  ${BOLD}Next Steps:${NC}"
    echo -e "  ${YELLOW}1.${NC} Build Rust:   cd $WORKSPACE/titan-tokio-api && cargo build --release"
    echo -e "  ${YELLOW}2.${NC} Install JDK:  pkg install openjdk-21"
    echo -e "  ${YELLOW}3.${NC} Build Kotlin: cd $WORKSPACE/titan-ktor-gateway && ./gradlew buildFatJar"
    echo -e "  ${YELLOW}4.${NC} Install Julia: $WORKSPACE/titan-julia-analytics/install_julia.sh"
    echo -e "  ${YELLOW}5.${NC} Start Kafka:  bash $WORKSPACE/kafka/start-kafka.sh"
    echo -e "  ${YELLOW}6.${NC} Start all:    bash $WORKSPACE/titan-start.sh"
    echo ""
    echo -e "  ${BOLD}Verify:${NC}"
    echo -e "  moat status"
    echo -e "  curl http://127.0.0.1:8080/health"
    echo -e "  curl http://127.0.0.1:8081/health"
    echo -e "  curl http://127.0.0.1:8082/analytics/mesh"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ══════════════════════════════════════════════════════════════════════════════
banner
mkdir -p "$WORKSPACE"

bind_device
gen_wireguard_keys
register_headscale
init_postgres
setup_kafka
write_tokio_service
write_kotlin_service
write_julia_service
write_supervisor
write_moat_v2

print_summary
