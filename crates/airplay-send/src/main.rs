// SPDX-License-Identifier: Apache-2.0
//
// airplay-send — ROADMAP.md m3: the CLI demo. `raop-sender`,
// `PosixTransport`, and `mdns-browser` are the library; this crate is
// just wiring + a wav reader + a credential cache, proving the whole
// thing on a real device in about 30 seconds:
//
//     airplay-send living_room.wav
//     airplay-send --host 10.0.0.42 --airplay1 song.wav
//     airplay-send --list
//
// See `--help` (or just run it) for the full option list. Port of
// `example/airplay_send.cpp` — same messages, exit codes (0/1/2), and
// control flow wherever the behavior is observable.

mod creds;
mod wav;

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use mdns_browser::{MdnsBrowser, RaopDeviceInfo};
use posix_transport::PosixTransport;
use raop_sender::session::{Auth as RaopAuth, Callbacks, Session};
use ring_buffer::RingBuffer;
use transport::Transport;

static G_STOP: AtomicBool = AtomicBool::new(false);

/// C++ calls `setVolume` from inside `onLaunched` — i.e. while the RTSP
/// handshake is still running — so the pending volume rides the RECORD
/// reply instead of arriving as a separate request. `set_volume` has the
/// same "stored now, sent when streaming starts" semantics, so call it
/// from the launch path to mirror that timing exactly.
fn session_apply_volume(holder: &Rc<RefCell<Option<Session>>>, pct: f64) {
    if let Some(s) = holder.borrow().as_ref() {
        s.set_volume(pct);
    }
}

fn auth_name(a: mdns_browser::Auth) -> &'static str {
    match a {
        mdns_browser::Auth::None => "none",
        mdns_browser::Auth::AuthSetup => "auth-setup",
        mdns_browser::Auth::LegacyPin => "legacy-pin",
        mdns_browser::Auth::HapTransient => "hap-transient",
        mdns_browser::Auth::HapPin => "hap-pin",
        mdns_browser::Auth::Password => "password",
    }
}

fn raop_auth(a: mdns_browser::Auth) -> RaopAuth {
    match a {
        mdns_browser::Auth::None => RaopAuth::NoAuth,
        mdns_browser::Auth::AuthSetup => RaopAuth::AuthSetup,
        mdns_browser::Auth::LegacyPin => RaopAuth::LegacyPin,
        mdns_browser::Auth::HapTransient => RaopAuth::HapTransient,
        mdns_browser::Auth::HapPin => RaopAuth::HapPin,
        mdns_browser::Auth::Password => RaopAuth::Password,
    }
}

fn trimmed(mut s: String) -> String {
    while let Some(&c) = s.as_bytes().first() {
        if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
            s.remove(0);
        } else {
            break;
        }
    }
    while let Some(&c) = s.as_bytes().last() {
        if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
            s.pop();
        } else {
            break;
        }
    }
    s
}

// std::stoi/std::stod throw on anything that isn't a valid number, which
// would crash the C++ on a typo'd flag value; these return `None` instead
// so callers can print a clean usage error. C++ accepts a leading space
// (stoi skips it) but rejects a trailing one (the `consumed != size`
// check); parsing the trimmed-start string mirrors that.
fn parse_int(s: &str) -> Option<i64> {
    if s.is_empty() {
        return None;
    }
    s.trim_start().parse::<i64>().ok()
}

fn parse_double(s: &str) -> Option<f64> {
    if s.is_empty() {
        return None;
    }
    s.trim_start().parse::<f64>().ok()
}

#[derive(Debug, PartialEq)]
struct Options {
    host: String, // empty = pick a device via mDNS
    port: u16,    // 0 = derive from --airplay1 / discovery
    airplay1: bool,
    password: String,
    // percent, applied once streaming starts; None = never send a volume
    // (the receiver keeps its own). Same policy as the C++ demo on the
    // miniaudio branch: defaulting this to 50 clobbered the receiver's
    // volume on every playback, which is a big problem.
    volume: Option<f64>,
    browse_seconds: i64,
    no_discover: bool,
    list: bool,
    help: bool,
    wav_path: String,
    device_id: String, // used when --host bypasses discovery's deviceId
}

impl Default for Options {
    fn default() -> Self {
        Options {
            host: String::new(),
            port: 0,
            airplay1: false,
            password: String::new(),
            volume: None,
            browse_seconds: 3,
            no_discover: false,
            list: false,
            help: false,
            wav_path: String::new(),
            device_id: String::new(),
        }
    }
}

fn print_usage(argv0: &str) {
    println!(
        "usage: {argv0} [options] <file.wav>\n\
         {argv0} --list\n\
         \n\
         stream a .wav file to an AirPlay / RAOP receiver.\n\
         \n\
         options:\n\
         \x20 --host <ip>          connect directly to this IP; skips picking a\n\
         \x20                      device from mDNS discovery (discovery still runs\n\
         \x20                      first, to fill in the port/auth/deviceId if this\n\
         \x20                      IP is seen; pass --no-discover to skip that too)\n\
         \x20 --port <port>        RTSP port (default: 7000, or 5000 with --airplay1;\n\
         \x20                      overrides whatever discovery found for --host)\n\
         \x20 --airplay1           force legacy AirPlay 1 (no HAP pairing)\n\
         \x20 --password <pw>      RTSP digest password (AirPlay 1 pw=true receivers)\n\
         \x20 --volume <0-100>     percent volume once streaming starts\n\
         \x20                      (default: leave untouched)\n\
         \x20 --browse-time <sec>  seconds to browse mDNS for (default: 3)\n\
         \x20 --no-discover        skip mDNS entirely (requires --host)\n\
         \x20 --device-id <id>     deviceId to pair as / look up cached\n\
         \x20                      credentials for (needed with --no-discover)\n\
         \x20 --list               print discovered devices and exit\n\
         \x20 -h, --help           this"
    );
}

/// Parse argv[1..]. `Err` carries the process exit code (2 = usage).
fn parse_args(args: &[String]) -> Result<Options, i32> {
    let mut o = Options::default();
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        let mut need = |flag: &str| -> Result<String, i32> {
            if i + 1 >= args.len() {
                eprintln!("error: {flag} needs a value");
                return Err(2);
            }
            i += 1;
            Ok(args[i].clone())
        };
        if a == "-h" || a == "--help" {
            o.help = true;
        } else if a == "--host" {
            o.host = need("--host")?;
        } else if a == "--port" {
            let v = need("--port")?;
            match parse_int(&v) {
                Some(p @ 1..=65535) => o.port = p as u16,
                _ => {
                    eprintln!("error: --port needs a number 1-65535, got '{v}'");
                    return Err(2);
                }
            }
        } else if a == "--airplay1" {
            o.airplay1 = true;
        } else if a == "--password" {
            o.password = need("--password")?;
        } else if a == "--volume" {
            let v = need("--volume")?;
            match parse_double(&v) {
                Some(d) => o.volume = Some(d),
                None => {
                    eprintln!("error: --volume needs a number, got '{v}'");
                    return Err(2);
                }
            }
        } else if a == "--browse-time" {
            let v = need("--browse-time")?;
            match parse_int(&v) {
                Some(s) if s >= 0 => o.browse_seconds = s,
                _ => {
                    eprintln!("error: --browse-time needs a non-negative number, got '{v}'");
                    return Err(2);
                }
            }
        } else if a == "--no-discover" {
            o.no_discover = true;
        } else if a == "--device-id" {
            o.device_id = need("--device-id")?;
        } else if a == "--list" {
            o.list = true;
        } else if !a.is_empty() && a.starts_with('-') {
            eprintln!("error: unknown option '{a}'");
            return Err(2);
        } else {
            positional.push(a);
        }
        i += 1;
    }
    if o.help || o.list {
        return Ok(o);
    }
    if positional.len() != 1 {
        eprintln!("error: expected exactly one <file.wav> argument");
        return Err(2);
    }
    o.wav_path = positional[0].clone();
    if o.no_discover && o.host.is_empty() {
        eprintln!("error: --no-discover requires --host");
        return Err(2);
    }
    Ok(o)
}

/// Browse for `seconds`; every device seen is appended to `out` (in
/// first-seen order, later updated in place on an mDNS "upgrade", same
/// semantics as `MdnsBrowser::query` itself).
fn browse(seconds: i64, out: &Rc<RefCell<Vec<RaopDeviceInfo>>>) {
    let Ok(browser) = MdnsBrowser::new() else {
        eprintln!(
            "warning: mDNS socket setup failed, discovery unavailable (firewall? try --host)"
        );
        return;
    };
    let out2 = out.clone();
    browser.query(Box::new(move |d| {
        let mut v = out2.borrow_mut();
        match v.iter_mut().find(|e| e.name == d.name) {
            Some(existing) => *existing = d.clone(),
            None => v.push(d.clone()),
        }
    }));
    let until = Instant::now() + Duration::from_secs(seconds.max(0) as u64);
    while Instant::now() < until {
        browser.poll(100);
    }
}

fn print_device(d: &RaopDeviceInfo) {
    print!(
        "{} {}  {}:{}",
        if d.airplay2 {
            "[AirPlay 2] "
        } else {
            "[AirPlay 1] "
        },
        d.name,
        d.host,
        d.port
    );
    if !d.model.is_empty() {
        print!("  ({})", d.model);
    }
    println!();
}

/// Resolve the device to actually connect to from discovery results +
/// the user's flags. `None` means nothing usable was found.
fn resolve_device(o: &Options, found: &[RaopDeviceInfo]) -> Option<RaopDeviceInfo> {
    let mut device;
    if !o.host.is_empty() {
        match found.iter().find(|d| d.host == o.host) {
            Some(it) => {
                device = it.clone();
                if o.port != 0 {
                    device.port = o.port; // explicit --port overrides discovery
                }
            }
            None => {
                // Not seen via mDNS (or discovery was skipped): build a
                // best guess from the flags. See mdns_browser's deriveAuth
                // for why "guess HapPin, let RaopSender's own 403/470
                // fallback sort it out" is the same honest default the
                // browser itself uses.
                device = RaopDeviceInfo {
                    name: o.host.clone(),
                    host: o.host.clone(),
                    port: if o.port != 0 {
                        o.port
                    } else if o.airplay1 {
                        5000
                    } else {
                        7000
                    },
                    txt: Default::default(),
                    device_id: o.device_id.clone(),
                    model: String::new(),
                    airplay2: !o.airplay1,
                    auth: if o.airplay1 {
                        if o.password.is_empty() {
                            mdns_browser::Auth::None
                        } else {
                            mdns_browser::Auth::Password
                        }
                    } else {
                        mdns_browser::Auth::HapPin
                    },
                };
                println!(
                    "note: {}; using port {}{}, auth={}{}.",
                    if o.no_discover {
                        "discovery skipped (--no-discover)".to_string()
                    } else {
                        format!("{} wasn't seen via mDNS", o.host)
                    },
                    device.port,
                    if o.port != 0 {
                        " (given)"
                    } else {
                        " (guessed)"
                    },
                    auth_name(device.auth),
                    if o.airplay1 {
                        " (--airplay1)"
                    } else {
                        " (guessed)"
                    }
                );
            }
        }
    } else {
        // Prefer an AirPlay 2 device; fall back to the first
        // AirPlay-1-only device, if any.
        device = found
            .iter()
            .find(|d| d.airplay2)
            .or_else(|| found.first())
            .cloned()?;
    }
    // Some receivers advertise no "deviceid" TXT key; fall back to the
    // host so the credential cache still has SOMETHING stable to key on.
    if device.device_id.is_empty() {
        device.device_id = device.host.clone();
    }
    Some(device)
}

fn main() {
    let argv0 = std::env::args()
        .next()
        .unwrap_or_else(|| "airplay-send".to_string());
    let args: Vec<String> = std::env::args().skip(1).collect();
    let o = match parse_args(&args) {
        Ok(o) => o,
        Err(code) => {
            print_usage(&argv0);
            std::process::exit(code);
        }
    };
    if o.help {
        print_usage(&argv0);
        return;
    }

    let found = Rc::new(RefCell::new(Vec::new()));
    if !o.no_discover {
        println!(
            "browsing for AirPlay/RAOP devices ({}s)...",
            o.browse_seconds
        );
        browse(o.browse_seconds, &found);
    }

    if o.list {
        let f = found.borrow();
        if f.is_empty() {
            println!("no devices found.");
        }
        for d in f.iter() {
            print_device(d);
        }
        return;
    }

    let Some(device) = resolve_device(&o, &found.borrow()) else {
        eprintln!(
            "error: no AirPlay device found. Try --host <ip>, --list, or a longer --browse-time."
        );
        std::process::exit(1);
    };
    println!("target: ");
    print_device(&device);

    let wav = match wav::load_wav(&o.wav_path) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "loaded '{}': {} frames @ {} Hz ({}s)",
        o.wav_path,
        wav.frames(),
        wav.sample_rate,
        wav.frames() as f64 / wav.sample_rate as f64
    );

    let cached_creds = creds::load_cached_creds(&device.device_id);
    if !cached_creds.is_empty() {
        println!("using cached credentials for this device");
    }

    let io = Rc::new(PosixTransport::new());

    // Roughly a second of stereo audio at the file's native rate; plenty
    // of headroom for the ~8 ms pacer to pull from without the feed loop
    // below needing to be especially tight about topping it up.
    let ring_size = wav.sample_rate.max(8000) as usize * 2;
    let ring = Rc::new(RefCell::new(RingBuffer::<i16>::new(ring_size)));

    // The PIN callback re-enters the session (submit_pin) from inside the
    // poll loop; the session handle is parked here until construction
    // completes. Callbacks cannot fire before start(), so this is always
    // populated by then.
    let session_holder: Rc<RefCell<Option<Session>>> = Rc::new(RefCell::new(None));
    let holder_for_cb = session_holder.clone();

    let launch_done = Rc::new(RefCell::new(false));
    let launched_ok = Rc::new(RefCell::new(false));
    let session_closed = Rc::new(RefCell::new(false));
    let ld = launch_done.clone();
    let lok = launched_ok.clone();
    let sc = session_closed.clone();
    let device_name = device.name.clone();
    let volume = o.volume;
    let volume_target = holder_for_cb.clone();

    let callbacks = Callbacks {
        on_launched: Box::new(move |ok, err| {
            *ld.borrow_mut() = true;
            *lok.borrow_mut() = ok;
            if ok {
                println!("streaming to '{device_name}'");
                if let Some(v) = volume {
                    session_apply_volume(&volume_target, v);
                }
            } else {
                eprintln!("error: {err}");
            }
        }),
        on_closed: Box::new(move || {
            *sc.borrow_mut() = true;
        }),
        on_pin_required: Box::new(move |name: &str| {
            // Blocks the poll loop while waiting for input, which is fine
            // here: there's nothing else useful to do concurrently in a
            // one-shot CLI tool, and the session's own PIN-wait watchdog
            // (3 min) just runs a little "late" relative to wall clock,
            // it's checked the instant poll() resumes after this returns,
            // not on a background thread.
            print!("\nenter the 4-digit AirPlay code shown on '{name}': ");
            let _ = std::io::stdout().flush();
            let mut pin = String::new();
            if std::io::stdin().read_line(&mut pin).is_ok() {
                if let Some(s) = holder_for_cb.borrow().as_ref() {
                    s.submit_pin(&trimmed(pin));
                }
            }
        }),
        on_credentials_obtained: Box::new(move |id, json| {
            creds::save_cached_creds(id, json);
            println!("paired; credentials cached for next time");
        }),
    };

    let session = Session::new(io.clone(), callbacks);
    *session_holder.borrow_mut() = Some(session.clone());
    session.attach_ring(ring.clone());
    session.set_input_format(wav.sample_rate);
    session.set_auth(
        raop_auth(device.auth),
        device.airplay2,
        &device.device_id,
        &cached_creds,
        &o.password,
    );

    let _ = ctrlc::set_handler(|| {
        G_STOP.store(true, Ordering::Relaxed);
    });

    session.start(&device.host, device.port, &device.name);

    let mut offset = 0usize;
    let total_samples = wav.pcm.len();
    let mut file_queued = false;
    let mut draining = false;
    let mut drain_deadline = Instant::now();
    let mut last_progress = Instant::now();

    while !G_STOP.load(Ordering::Relaxed) && !*session_closed.borrow() {
        while offset < total_samples {
            let avail = ring.borrow().available_write();
            if avail < 2 {
                break;
            }
            let mut chunk = avail.min(total_samples - offset);
            chunk -= chunk % 2; // keep stereo-frame alignment
            if chunk == 0 {
                break;
            }
            if !ring.borrow_mut().try_push(&wav.pcm[offset..offset + chunk]) {
                break;
            }
            offset += chunk;
        }
        if offset >= total_samples {
            file_queued = true;
        }

        io.poll(16);

        let now = Instant::now();
        if *launch_done.borrow()
            && *launched_ok.borrow()
            && now - last_progress >= Duration::from_millis(1000)
        {
            last_progress = now;
            let queued_sec = (offset / 2) as f64 / f64::from(wav.sample_rate);
            let total_sec = (total_samples / 2) as f64 / f64::from(wav.sample_rate);
            print!("\r{queued_sec}s / {total_sec}s queued   ");
            let _ = std::io::stdout().flush();
        }

        if file_queued && !draining && *launch_done.borrow() && ring.borrow().available_read() == 0
        {
            draining = true;
            // RAOP's fixed pipeline latency is ~1.5 s (see raop_sender.h);
            // give it a little extra margin so the last packets are
            // actually audible at the receiver before TEARDOWN.
            drain_deadline = now + Duration::from_millis(2500);
            println!("\nfile fully queued, letting the tail play out...");
        }
        if draining && now >= drain_deadline {
            break;
        }
    }

    println!();
    if G_STOP.load(Ordering::Relaxed) {
        println!("stopping (ctrl-c)...");
    }
    session.stop(); // synchronous: TEARDOWN + socket close happen inline
    println!("done");
    std::process::exit(if *launch_done.borrow() && !*launched_ok.borrow() {
        1
    } else {
        0
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_help_and_list_skip_wav_check() {
        let o = parse_args(&args(&["--help"])).unwrap();
        assert!(o.help);
        let o = parse_args(&args(&["--list"])).unwrap();
        assert!(o.list);
    }

    #[test]
    fn parse_requires_exactly_one_wav() {
        assert_eq!(parse_args(&args(&[])), Err(2));
        assert_eq!(parse_args(&args(&["a.wav", "b.wav"])), Err(2));
    }

    #[test]
    fn parse_unknown_option() {
        assert_eq!(parse_args(&args(&["--frobnicate", "a.wav"])), Err(2));
    }

    #[test]
    fn parse_option_values() {
        let o = parse_args(&args(&[
            "--host",
            "10.0.0.42",
            "--port",
            "6000",
            "--airplay1",
            "--password",
            "pw",
            "--volume",
            "80.5",
            "--browse-time",
            "7",
            "--no-discover",
            "song.wav",
        ]))
        .unwrap();
        assert_eq!(o.host, "10.0.0.42");
        assert_eq!(o.port, 6000);
        assert!(o.airplay1);
        assert_eq!(o.password, "pw");
        assert_eq!(o.volume, Some(80.5));
        assert_eq!(o.browse_seconds, 7);
        assert!(o.no_discover);
        assert_eq!(o.wav_path, "song.wav");
    }

    #[test]
    fn parse_port_validation() {
        assert_eq!(parse_args(&args(&["--port", "0", "a.wav"])), Err(2));
        assert_eq!(parse_args(&args(&["--port", "65536", "a.wav"])), Err(2));
        assert_eq!(parse_args(&args(&["--port", "abc", "a.wav"])), Err(2));
        assert_eq!(
            parse_args(&args(&["--port", "7000", "a.wav"]))
                .unwrap()
                .port,
            7000
        );
    }

    #[test]
    fn parse_volume_and_browse_time_validation() {
        assert_eq!(parse_args(&args(&["--volume", "x", "a.wav"])), Err(2));
        assert_eq!(parse_args(&args(&["--browse-time", "-1", "a.wav"])), Err(2));
        assert_eq!(parse_args(&args(&["--port"])), Err(2)); // needs a value
        // The default is None: without --volume nothing is ever pushed to
        // the receiver (its own volume stays put).
        assert_eq!(parse_args(&args(&["a.wav"])).unwrap().volume, None);
    }

    #[test]
    fn parse_no_discover_requires_host() {
        assert_eq!(parse_args(&args(&["--no-discover", "a.wav"])), Err(2));
    }

    #[test]
    fn parse_int_matches_stoi_consumption_semantics() {
        assert_eq!(parse_int(" 12"), Some(12)); // leading space OK (stoi skips)
        assert_eq!(parse_int("12 "), None); // trailing space: consumed != size
        assert_eq!(parse_int(""), None);
        assert_eq!(parse_int("1.5"), None);
        assert_eq!(parse_int("12x"), None);
    }

    #[test]
    fn trimmed_removes_whitespace_both_ends() {
        assert_eq!(trimmed("  1234\r\n".to_string()), "1234");
        assert_eq!(trimmed("\t007\t".to_string()), "007");
        assert_eq!(trimmed(String::new()), "");
        assert_eq!(trimmed(" no \n ".to_string()), "no");
    }

    fn dev(name: &str, host: &str, port: u16, ap2: bool) -> RaopDeviceInfo {
        RaopDeviceInfo {
            name: name.to_string(),
            host: host.to_string(),
            port,
            txt: Default::default(),
            device_id: format!("AA:{name}"),
            model: "TestModel".to_string(),
            airplay2: ap2,
            auth: mdns_browser::Auth::HapPin,
        }
    }

    #[test]
    fn resolve_picks_first_airplay2_then_falls_back() {
        let found = vec![dev("one", "10.0.0.1", 7000, false)];
        let o = Options::default();
        let r = resolve_device(&o, &found).unwrap();
        assert_eq!(r.name, "one"); // only AirPlay 1 device: picked anyway

        let found = vec![
            dev("a1", "10.0.0.1", 5000, false),
            dev("a2", "10.0.0.2", 7000, true),
        ];
        let r = resolve_device(&o, &found).unwrap();
        assert_eq!(r.name, "a2"); // AirPlay 2 preferred

        let r = resolve_device(&o, &[]);
        assert!(r.is_none());
    }

    #[test]
    fn resolve_host_seen_overrides_port() {
        let found = vec![dev("tv", "10.0.0.9", 7000, true)];
        let o = Options {
            host: "10.0.0.9".to_string(),
            port: 6500,
            ..Default::default()
        };
        let r = resolve_device(&o, &found).unwrap();
        assert_eq!(r.port, 6500);

        let o = Options {
            host: "10.0.0.9".to_string(),
            ..Default::default()
        };
        let r = resolve_device(&o, &found).unwrap();
        assert_eq!(r.port, 7000);
    }

    #[test]
    fn resolve_host_unknown_builds_guessed_device() {
        let o = Options {
            host: "10.0.0.99".to_string(),
            no_discover: true,
            ..Default::default()
        };
        let r = resolve_device(&o, &[]).unwrap();
        assert_eq!(r.port, 7000);
        assert!(r.airplay2);
        assert_eq!(r.auth, mdns_browser::Auth::HapPin);

        let o = Options {
            host: "10.0.0.99".to_string(),
            airplay1: true,
            no_discover: true,
            ..Default::default()
        };
        let r = resolve_device(&o, &[]).unwrap();
        assert_eq!(r.port, 5000);
        assert!(!r.airplay2);
        assert_eq!(r.auth, mdns_browser::Auth::None);

        let o = Options {
            host: "10.0.0.99".to_string(),
            airplay1: true,
            password: "secret".to_string(),
            no_discover: true,
            ..Default::default()
        };
        let r = resolve_device(&o, &[]).unwrap();
        assert_eq!(r.auth, mdns_browser::Auth::Password);
    }

    #[test]
    fn resolve_falls_back_device_id_to_host() {
        let mut found = vec![dev("tv", "10.0.0.9", 7000, true)];
        found[0].device_id = String::new();
        let o = Options::default();
        let r = resolve_device(&o, &found).unwrap();
        assert_eq!(r.device_id, "10.0.0.9");
    }
}
