//! UTC timestamps as plain `u64` microseconds since the unix epoch.
//! Everything is UTC+0 by construction; formatting is done with the
//! classic civil-from-days algorithm so no platform/locale code is involved.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current UTC time in microseconds since the unix epoch.
pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_micros() as u64
}

/// Format as RFC 3339 / ISO-8601 with microseconds, e.g. `2026-06-12T10:34:00.123456Z`.
pub fn format_rfc3339(micros: u64) -> String {
    let secs = (micros / 1_000_000) as i64;
    let sub = micros % 1_000_000;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day / 60) % 60,
        secs_of_day % 60,
    );
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{sub:06}Z")
}

/// Howard Hinnant's days-to-civil conversion (valid far beyond any audit horizon).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00.000000Z");
        // 2026-06-12T00:00:00Z == 1781222400
        assert_eq!(
            format_rfc3339(1_781_222_400_000_000),
            "2026-06-12T00:00:00.000000Z"
        );
    }
}
