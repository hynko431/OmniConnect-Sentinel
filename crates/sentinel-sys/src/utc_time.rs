//! Pure-Rust zero-dependency UTC timestamp and RFC 3339 formatting/parsing utilities.
//!
//! Replaces unmaintained external date crates (`RUSTSEC-2026-0543`) using `std::time::SystemTime`
//! and Howard Hinnant's proleptic Gregorian civil calendar formulas.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current wall-clock UTC timestamp as `(unix_secs, subsec_nanos)`.
pub fn now_unix_parts() -> (i64, u32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => (
            i64::try_from(dur.as_secs()).unwrap_or(i64::MAX),
            dur.subsec_nanos(),
        ),
        Err(err) => {
            let dur = err.duration();
            let secs = i64::try_from(dur.as_secs()).unwrap_or(0);
            let nanos = dur.subsec_nanos();
            if nanos == 0 {
                (-secs, 0)
            } else {
                (-(secs + 1), 1_000_000_000 - nanos)
            }
        }
    }
}

/// Returns the current wall-clock UTC time in seconds since Unix epoch (`1970-01-01T00:00:00Z`).
pub fn now_unix_secs() -> i64 {
    now_unix_parts().0
}

/// Returns both the current Unix epoch seconds and RFC 3339 UTC string captured from a single clock read.
pub fn now_unix_and_rfc3339_utc() -> (i64, String) {
    let (secs, nanos) = now_unix_parts();
    (secs, unix_to_rfc3339_utc(secs, nanos))
}

/// Returns the current wall-clock UTC time formatted as an RFC 3339 string (`YYYY-MM-DDTHH:MM:SS(.nnnnnnnnn)Z`).
pub fn now_rfc3339_utc() -> String {
    let (secs, nanos) = now_unix_parts();
    unix_to_rfc3339_utc(secs, nanos)
}

/// Converts Unix epoch seconds + subsecond nanoseconds to an RFC 3339 UTC timestamp string.
pub fn unix_to_rfc3339_utc(secs: i64, nanos: u32) -> String {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u32;
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;
    let (year, month, day) = civil_from_days(days);
    let clamped_nanos = nanos.min(999_999_999);
    if clamped_nanos == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{clamped_nanos:09}Z"
        )
    }
}

/// Parses an RFC 3339 timestamp string (`YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)`) into Unix epoch seconds.
pub fn parse_rfc3339_utc_unix(input: &str) -> Result<i64, String> {
    let s = input.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return Err(format!("RFC 3339 timestamp too short: '{s}'"));
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || (bytes[10] != b'T' && bytes[10] != b't' && bytes[10] != b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(format!("Malformed RFC 3339 date/time separators: '{s}'"));
    }

    let year: i64 = s[0..4]
        .parse()
        .map_err(|_| format!("Invalid RFC 3339 year in '{s}'"))?;
    let month: u32 = s[5..7]
        .parse()
        .map_err(|_| format!("Invalid RFC 3339 month in '{s}'"))?;
    let day: u32 = s[8..10]
        .parse()
        .map_err(|_| format!("Invalid RFC 3339 day in '{s}'"))?;
    let hour: u32 = s[11..13]
        .parse()
        .map_err(|_| format!("Invalid RFC 3339 hour in '{s}'"))?;
    let minute: u32 = s[14..16]
        .parse()
        .map_err(|_| format!("Invalid RFC 3339 minute in '{s}'"))?;
    let second: u32 = s[17..19]
        .parse()
        .map_err(|_| format!("Invalid RFC 3339 second in '{s}'"))?;

    if !(1..=12).contains(&month) {
        return Err(format!("RFC 3339 month out of range: {month}"));
    }
    let max_day = days_in_month(year, month);
    if day < 1 || day > max_day {
        return Err(format!(
            "RFC 3339 day {day} out of range for {year:04}-{month:02}"
        ));
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(format!(
            "RFC 3339 time out of range: {hour:02}:{minute:02}:{second:02}"
        ));
    }

    let mut rest = &s[19..];
    if let Some(after_dot) = rest.strip_prefix('.') {
        let frac_len = after_dot.bytes().take_while(|b| b.is_ascii_digit()).count();
        if frac_len == 0 {
            return Err(format!("Empty RFC 3339 fractional seconds in '{s}'"));
        }
        rest = &after_dot[frac_len..];
    }

    let tz_offset_secs: i64 = if rest == "Z" || rest == "z" {
        0
    } else if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) {
        let rb = rest.as_bytes();
        if rb[3] != b':' {
            return Err(format!("Malformed RFC 3339 timezone offset: '{rest}'"));
        }
        let tz_h: i64 = rest[1..3]
            .parse()
            .map_err(|_| format!("Invalid RFC 3339 timezone hour: '{rest}'"))?;
        let tz_m: i64 = rest[4..6]
            .parse()
            .map_err(|_| format!("Invalid RFC 3339 timezone minute: '{rest}'"))?;
        if tz_h > 23 || tz_m > 59 {
            return Err(format!("RFC 3339 timezone offset out of range: '{rest}'"));
        }
        let mag = tz_h * 3600 + tz_m * 60;
        if rest.starts_with('+') {
            mag
        } else {
            -mag
        }
    } else {
        return Err(format!(
            "Missing or invalid RFC 3339 timezone suffix: '{s}'"
        ));
    };

    let days = days_from_civil(year, month, day);
    let local_secs = days
        .checked_mul(86_400)
        .and_then(|v| {
            v.checked_add(i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))
        })
        .ok_or_else(|| format!("RFC 3339 timestamp overflow: '{s}'"))?;
    local_secs
        .checked_sub(tz_offset_secs)
        .ok_or_else(|| format!("RFC 3339 timezone offset overflow: '{s}'"))
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Howard Hinnant's `civil_from_days` converting days since `1970-01-01` to `(year, month, day)`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + i64::from(m <= 2);
    (y, m as u32, d as u32)
}

/// Howard Hinnant's `days_from_civil` converting `(year, month, day)` to days since `1970-01-01`.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64;
    let m_adj = if month > 2 {
        u64::from(month - 3)
    } else {
        u64::from(month + 9)
    };
    let doy = (153 * m_adj + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_rfc3339_format_and_parse_known_dates() {
        assert_eq!(unix_to_rfc3339_utc(0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(parse_rfc3339_utc_unix("1970-01-01T00:00:00Z").ok(), Some(0));

        assert_eq!(
            unix_to_rfc3339_utc(1_795_262_400, 0),
            "2026-11-21T12:00:00Z"
        );
        assert_eq!(
            parse_rfc3339_utc_unix("2026-11-21T12:00:00Z").ok(),
            Some(1_795_262_400)
        );
        assert_eq!(
            parse_rfc3339_utc_unix("2026-11-21T17:30:00.123456+05:30").ok(),
            Some(1_795_262_400)
        );

        // Leap years (2000, 2024) and non-leap century (1900, 2100)
        assert_eq!(
            unix_to_rfc3339_utc(951_782_400, 500_000_000),
            "2000-02-29T00:00:00.500000000Z"
        );
        assert_eq!(
            parse_rfc3339_utc_unix("2024-02-29T23:59:59Z").ok(),
            Some(1_709_251_199)
        );
        assert!(parse_rfc3339_utc_unix("1900-02-29T00:00:00Z").is_err());
        assert!(parse_rfc3339_utc_unix("2100-02-29T00:00:00Z").is_err());
        assert!(parse_rfc3339_utc_unix("2026-13-01T00:00:00Z").is_err());
        assert!(parse_rfc3339_utc_unix("2026-11-21T24:00:00Z").is_err());

        // Live clock sanity
        let (secs, formatted) = now_unix_and_rfc3339_utc();
        assert!(secs > 1_700_000_000);
        assert!(formatted.ends_with('Z'));
        assert_eq!(parse_rfc3339_utc_unix(&formatted).ok(), Some(secs));
    }
}
