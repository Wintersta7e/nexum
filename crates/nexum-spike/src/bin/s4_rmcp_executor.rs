//! Spike S4 — rmcp + executor split + semaphore saturation
//!
//! Pass criteria (per design §3.6 S4):
//!   - Build a minimal rmcp server with two tools: `slow_op` (semaphore-gated, dispatches to a
//!     rayon pool) and `fast_op` (immediate return). Default `max_outstanding_jobs = 32`.
//!   - Phase (i): 16 slow_op + 16 fast_op (under cap). fast_op median latency <50 ms even with
//!     16 slow_op in flight (handlers don't block on CPU).
//!   - Phase (ii): 64 slow_op exceeds 32-cap. Calls 33+ await up to wait_timeout; on timeout
//!     return Busy { retry_after_ms }; on permit they execute.
//!   - Phase (iii): 64 sync `embed_blocking` callers via `try_acquire` see Busy { retry_after_ms: 0 }
//!     immediately (no async wait).
//!
//! What this validates: that the §3 executor split (tokio runtime for handler dispatch + rayon
//! pool for CPU work + tokio::Semaphore for backpressure) actually delivers responsive handlers
//! under concurrent indexing — i.e., the semaphore bounds outstanding jobs, not just executor
//! concurrency (Codex v4 🟠#1).
//!
//! What this does NOT exercise: rmcp's stdio/sse transport or framing. The executor model is
//! what's under test; transport correctness is exercised separately in §6 MCP tool surface
//! tests during M1. The rmcp wiring is here to confirm compile-time integration with our
//! chosen tokio + rayon shape — i.e., that rmcp's macros + handler traits accept our handler
//! signatures and don't impose conflicting Send/Sync/runtime constraints.
//!
//! Throwaway. Same self-contained pattern as S1 + S2.

#![allow(
    // Spike-only: timing-arithmetic conversions across integer/float widths.
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    // Phase-local names like `slow_results` / `slow_handles` differ by one identifier.
    clippy::similar_names,
    // Spike `main` is end-to-end orchestration mirroring the spec's three-phase checklist.
    clippy::too_many_lines,
)]

use anyhow::Result;
use rayon::ThreadPool;
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const MAX_OUTSTANDING_JOBS: usize = 32;
const SLOW_OP_DURATION_MS: u64 = 2000;
const WAIT_TIMEOUT_MS: u64 = 500;
const FAST_OP_LATENCY_TARGET_MS: u128 = 50;
const RAYON_THREADS: usize = 4;

const PHASE1_SLOW: usize = 16;
const PHASE1_FAST: usize = 16;
const PHASE2_SLOW: usize = 64;
const PHASE3_SYNC: usize = 64;

// ============================================================================
// EmbedServer — minimal rmcp server with the §3 executor model
// ============================================================================

#[derive(Clone)]
struct EmbedServer {
    semaphore: Arc<Semaphore>,
    rayon_pool: Arc<ThreadPool>,
    wait_timeout: Duration,
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
}

impl EmbedServer {
    fn new(rayon_pool: Arc<ThreadPool>) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(MAX_OUTSTANDING_JOBS)),
            rayon_pool,
            wait_timeout: Duration::from_millis(WAIT_TIMEOUT_MS),
            tool_router: Self::tool_router(),
        }
    }

    /// Sync embed entry mirroring `embed_blocking` from §3. Non-blocking — `try_acquire`
    /// returns immediately. Used by sync callers that cannot await (e.g., extraction
    /// pipelines triggered from synchronous codepaths).
    fn embed_blocking(&self) -> std::result::Result<(), BusyError> {
        let _permit = self
            .semaphore
            .try_acquire()
            .map_err(|_| BusyError { retry_after_ms: 0 })?;
        // Simulated immediate work; real path would do CPU work here on the calling thread.
        std::thread::sleep(Duration::from_millis(1));
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct BusyError {
    retry_after_ms: u64,
}

#[tool_router(router = tool_router)]
impl EmbedServer {
    #[tool(description = "Slow embedding op; semaphore-gated, rayon-dispatched")]
    async fn slow_op(&self) -> String {
        let permit = match tokio::time::timeout(
            self.wait_timeout,
            self.semaphore.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return "BUSY: semaphore closed".to_owned(),
            Err(_) => {
                return format!(
                    "BUSY: wait_timeout {}ms exceeded; retry_after_ms=100",
                    self.wait_timeout.as_millis()
                );
            }
        };

        let pool = self.rayon_pool.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        pool.spawn(move || {
            std::thread::sleep(Duration::from_millis(SLOW_OP_DURATION_MS));
            drop(permit);
            let _ = tx.send(());
        });

        match rx.await {
            Ok(()) => "OK".to_owned(),
            Err(_) => "BUSY: rayon channel dropped".to_owned(),
        }
    }

    #[tool(description = "Fast non-blocking op; returns immediately")]
    async fn fast_op(&self) -> String {
        "FAST".to_owned()
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for EmbedServer {}

// ============================================================================
// main — drive the three test phases
// ============================================================================

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_tracing();

    let rayon_pool = Arc::new(
        rayon::ThreadPoolBuilder::new()
            .num_threads(RAYON_THREADS)
            .thread_name(|i| format!("nexum-spike-rayon-{i}"))
            .build()?,
    );
    let server = EmbedServer::new(rayon_pool);
    let mut report = Report::new();
    report.pass(
        "setup",
        &format!(
            "EmbedServer ready. MAX_OUTSTANDING_JOBS={MAX_OUTSTANDING_JOBS}, \
             RAYON_THREADS={RAYON_THREADS}, SLOW_OP={SLOW_OP_DURATION_MS}ms, \
             WAIT_TIMEOUT={WAIT_TIMEOUT_MS}ms"
        ),
    );

    // ------------------------------------------------------------------------
    // PHASE i — UNDER CAP: 16 slow + 16 fast.
    // Spawn 16 slow_ops first (they take a 2 s permit each). Then time 16 fast_op calls.
    // The handlers must not be blocked by CPU — fast_op median latency must stay tiny.
    // ------------------------------------------------------------------------
    let mut slow_set = JoinSet::new();
    for _ in 0..PHASE1_SLOW {
        let s = server.clone();
        slow_set.spawn(async move { s.slow_op().await });
    }

    // Let slow_ops claim their permits and dispatch to rayon.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut fast_latencies_ms = Vec::with_capacity(PHASE1_FAST);
    for _ in 0..PHASE1_FAST {
        let t0 = Instant::now();
        let result = server.fast_op().await;
        let dt_ms = t0.elapsed().as_micros() / 1000;
        assert_eq!(result, "FAST");
        fast_latencies_ms.push(dt_ms);
    }
    fast_latencies_ms.sort_unstable();
    let median_ms = fast_latencies_ms[PHASE1_FAST / 2];
    let max_ms = *fast_latencies_ms.last().unwrap_or(&0);

    let mut slow_results = Vec::with_capacity(PHASE1_SLOW);
    while let Some(joined) = slow_set.join_next().await {
        slow_results.push(joined.unwrap_or_else(|e| format!("PANIC: {e}")));
    }
    let slow_ok = slow_results.iter().filter(|s| s.as_str() == "OK").count();

    report.assert(
        "phase-i-under-cap",
        median_ms < FAST_OP_LATENCY_TARGET_MS && slow_ok == PHASE1_SLOW,
        &format!(
            "fast_op latency median={median_ms}ms max={max_ms}ms (target median \
             <{FAST_OP_LATENCY_TARGET_MS}ms with {PHASE1_SLOW} slow_op in flight); \
             slow_op success: {slow_ok}/{PHASE1_SLOW}"
        ),
    );

    // ------------------------------------------------------------------------
    // PHASE ii — OVER CAP: 64 slow_op.
    // First 32 grab permits and start 2 s work. Calls 33..64 await up to wait_timeout
    // (500 ms). Since slow_ops take 2 s, the wait expires before any permit frees → 32
    // jobs return BUSY. Validates: semaphore actually bounds backpressure (Codex v4 🟠#1),
    // not just executor concurrency.
    // ------------------------------------------------------------------------
    let mut over_cap_set = JoinSet::new();
    let phase2_start = Instant::now();
    for _ in 0..PHASE2_SLOW {
        let s = server.clone();
        over_cap_set.spawn(async move { s.slow_op().await });
    }
    let mut over_cap_results = Vec::with_capacity(PHASE2_SLOW);
    while let Some(joined) = over_cap_set.join_next().await {
        over_cap_results.push(joined.unwrap_or_else(|e| format!("PANIC: {e}")));
    }
    let phase2_wall_ms = phase2_start.elapsed().as_millis();
    let ok = over_cap_results.iter().filter(|s| s.as_str() == "OK").count();
    let busy = over_cap_results
        .iter()
        .filter(|s| s.starts_with("BUSY"))
        .count();
    let expected_busy = PHASE2_SLOW - MAX_OUTSTANDING_JOBS;

    report.assert(
        "phase-ii-over-cap",
        ok == MAX_OUTSTANDING_JOBS && busy == expected_busy,
        &format!(
            "after {phase2_wall_ms}ms wall: {ok} OK + {busy} BUSY out of {PHASE2_SLOW} \
             (expected {MAX_OUTSTANDING_JOBS} OK + {expected_busy} BUSY); semaphore bounded \
             outstanding jobs to {MAX_OUTSTANDING_JOBS}"
        ),
    );

    // ------------------------------------------------------------------------
    // PHASE iii — SYNC try_acquire under saturation.
    // Saturate the semaphore with 32 async holders. Then drive 64 sync embed_blocking calls.
    // try_acquire is non-blocking — every sync call should return Busy immediately.
    // ------------------------------------------------------------------------
    let mut hold_set = JoinSet::new();
    for _ in 0..MAX_OUTSTANDING_JOBS {
        let sem = server.semaphore.clone();
        hold_set.spawn(async move {
            if let Ok(permit) = sem.acquire_owned().await {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                drop(permit);
            }
        });
    }
    // Let the holders claim all permits.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let phase3_start = Instant::now();
    let mut sync_ok = 0_usize;
    let mut sync_busy = 0_usize;
    for _ in 0..PHASE3_SYNC {
        match server.embed_blocking() {
            Ok(()) => sync_ok += 1,
            Err(BusyError { retry_after_ms }) => {
                // Spec invariant (§3): sync callers see Busy with retry_after_ms == 0.
                assert_eq!(retry_after_ms, 0, "spec: sync try_acquire Busy must be immediate");
                sync_busy += 1;
            }
        }
    }
    let phase3_wall_ms = phase3_start.elapsed().as_millis();

    report.assert(
        "phase-iii-sync-busy",
        sync_ok == 0 && sync_busy == PHASE3_SYNC && phase3_wall_ms < 200,
        &format!(
            "{sync_busy} immediate Busy returns out of {PHASE3_SYNC} sync calls; total wall \
             = {phase3_wall_ms}ms (expected <200ms — try_acquire is non-blocking)"
        ),
    );

    // Drain the holders (they auto-release after 1.5 s sleep; this just keeps the runtime
    // honest before exit).
    while hold_set.join_next().await.is_some() {}

    // Compile-time validation NOTE — rmcp wiring exists; transport is not exercised here.
    report.note(
        "rmcp-compile-validation",
        "rmcp 1.5 #[tool_router] + #[tool] + #[tool_handler] all compile cleanly with our \
         tokio multi-thread runtime + rayon pool + Semaphore-bounded async handlers. The \
         spike's three phases drive handler methods directly in-process; the transport layer \
         (stdio/sse) is exercised in M1's §6 MCP tool surface tests, not here.",
    );

    report.print();
    if report.all_pass() {
        Ok(())
    } else {
        std::process::exit(1)
    }
}

// ============================================================================
// reporting (same shape as S1/S2)
// ============================================================================

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();
}

#[derive(Debug)]
struct Report {
    rows: Vec<ReportRow>,
}

#[derive(Debug)]
enum ReportRow {
    Pass { name: String, detail: String },
    Fail { name: String, detail: String },
    Note { name: String, detail: String },
}

impl Report {
    fn new() -> Self {
        Self { rows: Vec::new() }
    }
    fn pass(&mut self, name: &str, detail: &str) {
        self.rows.push(ReportRow::Pass {
            name: name.into(),
            detail: detail.into(),
        });
    }
    #[allow(dead_code)]
    fn fail(&mut self, name: &str, detail: &str) {
        self.rows.push(ReportRow::Fail {
            name: name.into(),
            detail: detail.into(),
        });
    }
    fn note(&mut self, name: &str, detail: &str) {
        self.rows.push(ReportRow::Note {
            name: name.into(),
            detail: detail.into(),
        });
    }
    fn assert(&mut self, name: &str, condition: bool, detail: &str) {
        if condition {
            self.pass(name, detail);
        } else {
            self.fail(name, detail);
        }
    }
    fn all_pass(&self) -> bool {
        !self.rows.iter().any(|r| matches!(r, ReportRow::Fail { .. }))
    }
    fn print(&self) {
        println!("\n=== nexum spike S4 — rmcp + executor split + semaphore saturation ===\n");
        for row in &self.rows {
            match row {
                ReportRow::Pass { name, detail } => println!("  PASS  [{name}] {detail}"),
                ReportRow::Fail { name, detail } => println!("  FAIL  [{name}] {detail}"),
                ReportRow::Note { name, detail } => println!("  NOTE  [{name}] {detail}"),
            }
        }
        let passes = self
            .rows
            .iter()
            .filter(|r| matches!(r, ReportRow::Pass { .. }))
            .count();
        let fails = self
            .rows
            .iter()
            .filter(|r| matches!(r, ReportRow::Fail { .. }))
            .count();
        let notes = self
            .rows
            .iter()
            .filter(|r| matches!(r, ReportRow::Note { .. }))
            .count();
        println!("\n  --- {passes} pass / {fails} fail / {notes} note(s) ---\n");
    }
}
