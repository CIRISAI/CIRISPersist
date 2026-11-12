//! CIRISPersist#1261 probe: replay `SqliteBackend::open_with_readers`
//! step by step against the platform SQLite, reporting the extended result
//! code and errno at each step.
use rusqlite::{ffi, Connection};
use std::ffi::{CStr, CString};
use std::path::Path;

const WRITER_PRAGMAS: &str = "PRAGMA foreign_keys = ON;\n\
     PRAGMA journal_mode = WAL;\n\
     PRAGMA synchronous = NORMAL;\n\
     PRAGMA busy_timeout = 30000;\n\
     PRAGMA wal_autocheckpoint = 1000;\n\
     PRAGMA journal_size_limit = 67108864;";
// #1246 tuning as shipped (no cgroup on macOS → 1 GiB cap).
const TUNING: &str = "PRAGMA mmap_size = 1073741824;\nPRAGMA cache_size = -32768;";
const READER_PRAGMAS: [&str; 3] = [
    "PRAGMA foreign_keys = ON",
    "PRAGMA busy_timeout = 30000",
    "PRAGMA query_only = ON",
];
const RO: i32 = ffi::SQLITE_OPEN_READONLY;
const NOMUTEX: i32 = ffi::SQLITE_OPEN_NOMUTEX;
const URI: i32 = ffi::SQLITE_OPEN_URI;

unsafe fn diag(db: *mut ffi::sqlite3) -> String {
    if db.is_null() {
        return "db=null".into();
    }
    format!(
        "ext={} errno={} msg={:?}",
        ffi::sqlite3_extended_errcode(db),
        ffi::sqlite3_system_errno(db),
        CStr::from_ptr(ffi::sqlite3_errmsg(db)).to_string_lossy()
    )
}

unsafe fn exec(db: *mut ffi::sqlite3, sql: &str) -> String {
    let c = CString::new(sql).unwrap();
    let mut err: *mut std::os::raw::c_char = std::ptr::null_mut();
    let rc = ffi::sqlite3_exec(db, c.as_ptr(), None, std::ptr::null_mut(), &mut err);
    if !err.is_null() {
        ffi::sqlite3_free(err as *mut _);
    }
    if rc == 0 {
        "ok".into()
    } else {
        format!("rc={rc} {}", diag(db))
    }
}

fn sizes(p: &Path) -> String {
    ["", "-wal", "-shm"]
        .iter()
        .map(|s| {
            let f = format!("{}{s}", p.display());
            match std::fs::metadata(&f) {
                Ok(m) => format!("db{s}={}", m.len()),
                Err(_) => format!("db{s}=absent"),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// One reader, opened the way ReadPool::open opens it, then its pragmas,
/// the tuning, and a first read — each step reported.
fn reader(path: &str, flags: i32, tuning: bool) -> String {
    unsafe {
        let c = CString::new(path).unwrap();
        let mut db = std::ptr::null_mut();
        let rc = ffi::sqlite3_open_v2(c.as_ptr(), &mut db, flags, std::ptr::null());
        let mut out = vec![format!("open rc={rc} {}", if rc == 0 { "ok".into() } else { diag(db) })];
        if rc == 0 {
            for p in READER_PRAGMAS {
                out.push(format!("[{p}] {}", exec(db, p)));
            }
            if tuning {
                for p in TUNING.split('\n') {
                    out.push(format!("[{p}] {}", exec(db, p)));
                }
            }
            out.push(format!("[read] {}", exec(db, "SELECT count(*) FROM sqlite_master")));
        }
        ffi::sqlite3_close(db);
        out.join("\n      ")
    }
}

fn scenario(name: &str, writer_tuning: bool, write_first: bool, flags: i32, reader_tuning: bool) {
    scenario2(name, writer_tuning, write_first, flags, reader_tuning, "", false)
}

/// `prime` is SQL the writer runs after its pragmas, before any reader opens.
/// `reopen` first creates the store, writes, closes it (SQLite deletes the
/// -wal/-shm on a clean last close), then reopens: the node-restart case.
fn scenario2(name: &str, writer_tuning: bool, write_first: bool, flags: i32, reader_tuning: bool, prime: &str, reopen: bool) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("persist.db");
    let path = p.to_str().unwrap().to_string();
    if reopen {
        let w0 = Connection::open(&path).unwrap();
        w0.execute_batch(WRITER_PRAGMAS).unwrap();
        w0.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (1);").unwrap();
        drop(w0);
        println!("   (reopen: after clean close {})", sizes(&p));
    }
    let w = Connection::open(&path).unwrap();
    let wr = w.execute_batch(WRITER_PRAGMAS);
    let jm: String = w.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap_or_default();
    if writer_tuning {
        w.execute_batch(TUNING).unwrap();
    }
    if write_first {
        w.execute_batch("CREATE TABLE IF NOT EXISTS t(x)").unwrap();
    }
    if !prime.is_empty() {
        let r = w.query_row(prime, [], |r| r.get::<_, i64>(0));
        println!("   prime {prime:?} -> {r:?}, {}", sizes(&p));
    }
    println!("== {name}");
    println!("   writer pragmas {:?}, journal_mode={jm}, {}", wr.map(|_| ()), sizes(&p));
    for i in 0..2 {
        println!("   reader {i}: {}", reader(&path, flags, reader_tuning));
    }
    // What rusqlite itself reports for the same open (what persist surfaces).
    let rs = Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::from_bits_truncate(flags),
    )
    .and_then(|c| c.execute_batch("PRAGMA query_only = ON; SELECT count(*) FROM sqlite_master;").map(|_| ()));
    println!("   rusqlite open+read: {rs:?}");
    println!("   after: {}", sizes(&p));
    drop(w);
}

fn main() {
    unsafe {
        println!(
            "sqlite runtime {} ({}), header {}",
            CStr::from_ptr(ffi::sqlite3_libversion()).to_string_lossy(),
            ffi::sqlite3_libversion_number(),
            ffi::SQLITE_VERSION_NUMBER
        );
    }
    let c = Connection::open_in_memory().unwrap();
    let mut st = c.prepare("PRAGMA compile_options").unwrap();
    let opts: Vec<String> = st.query_map([], |r| r.get(0)).unwrap().filter_map(|r| r.ok()).collect();
    println!("compile_options: {}", opts.join(" "));
    println!("TMPDIR={:?}", std::env::var("TMPDIR"));

    let f = RO | NOMUTEX | URI;
    scenario("A 61.2.2 as shipped (writer+reader tuning)", true, false, f, true);
    scenario("B 61.0.5 sequence (no tuning)", false, false, f, false);
    scenario("C writer tuning only", true, false, f, false);
    scenario("D reader tuning only", false, false, f, true);
    scenario("E as shipped, writer writes first", true, true, f, true);
    scenario("F as shipped, flags RO only", true, false, RO, true);
    scenario("G as shipped, flags RO|URI", true, false, RO | URI, true);
    scenario("H as shipped, mmap 0", false, false, f, false);
    let prime = "SELECT count(*) FROM sqlite_master";
    scenario2("I as shipped, writer READS first (the fix)", true, false, f, true, prime, false);
    scenario2("J restart: reopen existing, no prime", true, false, f, true, "", true);
    scenario2("K restart: reopen existing, writer reads first", true, false, f, true, prime, true);
    scenario2("L as shipped, prime = PRAGMA schema_version", true, false, f, true, "PRAGMA schema_version", false);
}
