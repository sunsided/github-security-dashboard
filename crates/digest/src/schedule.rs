//! When digests are due.

use chrono::{DateTime, Days, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;

/// A time of day in a time zone, once per day.
#[derive(Debug, Clone, Copy)]
pub struct DailySlot {
    pub at: NaiveTime,
    pub timezone: Tz,
}

impl DailySlot {
    /// The slot on the local calendar day of `now`. On days where `at`
    /// doesn't exist (skipped by a DST change) the next valid instant is
    /// used; where it exists twice, the first.
    fn on_day_of(&self, now: DateTime<Utc>, offset_days: i64) -> DateTime<Utc> {
        let local_day = now.with_timezone(&self.timezone).date_naive();
        let day = if offset_days >= 0 {
            local_day + Days::new(offset_days as u64)
        } else {
            local_day - Days::new(offset_days.unsigned_abs())
        };
        let mut naive = day.and_time(self.at);
        loop {
            match self.timezone.from_local_datetime(&naive) {
                chrono::LocalResult::Single(t) | chrono::LocalResult::Ambiguous(t, _) => {
                    return t.with_timezone(&Utc);
                }
                chrono::LocalResult::None => naive += chrono::Duration::minutes(15),
            }
        }
    }

    /// The most recent slot at or before `now`.
    pub fn previous(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        let today = self.on_day_of(now, 0);
        if today <= now {
            today
        } else {
            self.on_day_of(now, -1)
        }
    }

    /// The first slot after `now`.
    pub fn next(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        let today = self.on_day_of(now, 0);
        if today > now {
            today
        } else {
            self.on_day_of(now, 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    fn utc(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    fn berlin_8am() -> DailySlot {
        DailySlot {
            at: NaiveTime::from_hms_opt(8, 0, 0).unwrap(),
            timezone: chrono_tz::Europe::Berlin,
        }
    }

    #[test]
    fn slots_follow_the_local_clock() {
        let slot = berlin_8am();
        // October: CEST, UTC+2.
        check!(slot.previous(utc("2026-10-17T07:30:00Z")) == utc("2026-10-17T06:00:00Z"));
        check!(slot.next(utc("2026-10-17T07:30:00Z")) == utc("2026-10-18T06:00:00Z"));
        check!(slot.previous(utc("2026-10-17T05:59:00Z")) == utc("2026-10-16T06:00:00Z"));
        check!(slot.next(utc("2026-10-17T05:59:00Z")) == utc("2026-10-17T06:00:00Z"));
        // Exactly at the slot: it is the previous one, the next is tomorrow.
        check!(slot.previous(utc("2026-10-17T06:00:00Z")) == utc("2026-10-17T06:00:00Z"));
        check!(slot.next(utc("2026-10-17T06:00:00Z")) == utc("2026-10-18T06:00:00Z"));
    }

    #[test]
    fn daylight_saving_changes_move_the_utc_time() {
        let slot = berlin_8am();
        // The night of 2026-10-25 switches back to CET, UTC+1.
        check!(slot.next(utc("2026-10-24T12:00:00Z")) == utc("2026-10-25T07:00:00Z"));
    }

    #[test]
    fn skipped_local_times_use_the_next_valid_instant() {
        // 02:30 doesn't exist in Berlin on 2026-03-29 (clocks jump 02:00 -> 03:00).
        let slot = DailySlot {
            at: NaiveTime::from_hms_opt(2, 30, 0).unwrap(),
            timezone: chrono_tz::Europe::Berlin,
        };
        check!(slot.next(utc("2026-03-28T12:00:00Z")) == utc("2026-03-29T01:00:00Z"));
    }
}
