//! CIRISPersist#1198 (CC 4.5.13, `CLM-vote-once-per-person`; CC 3.3.6.3) —
//! **the person behind a key.** A roster seats a key; the person is the fedID
//! whose self roster the key belongs to; a tally counts fedIDs.
//!
//! [`KeySelves`] holds what the directory says about a set of keys, and
//! [`PersonsAt`] answers from it at one instant, with no further read, the
//! same split as [`NodeBearingSeats`](super::NodeBearingSeats): the roster
//! fold asks at every event's instant and stays pure.
//!
//! Two questions, because a seat outlives the device in it:
//!
//! - [`PersonsAt::seat_person`] — whose seat is this key's? The live self of
//!   the key, else the self it last belonged to, else the key itself. An
//!   evicted device's seat stays its person's, so losing a phone costs the
//!   device its voice and the person nothing.
//! - [`PersonsAt::voice`] — whom does this key's signature speak for? The
//!   live self of the key, or the key itself when it never belonged to one.
//!   `None` for a key that has left its self, and for a key on two rosters,
//!   which names no one person. That row is held and counts for nothing.
//!
//! Per-key counting on the self-roster plane (`self_roster`, `two_path`) is
//! not this: there the keys are the voters.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

use super::self_roster::{genesis_evicted_since, is_user_key, roster_assertion_live};
use super::{Error, FederationDirectory, InstantInterval};

/// One self's roster history of one key.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RosterHistory {
    identity: String,
    asserted: Vec<InstantInterval>,
    revocations: Vec<DateTime<Utc>>,
}

/// What the directory holds about one key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct KeyFacts {
    /// The key is user-role; another role is on no self roster
    /// ([`is_roster_key_at`](super::self_roster::is_roster_key_at)).
    user: bool,
    /// As a genesis key, it was evicted from this instant.
    evicted_since: Option<DateTime<Utc>>,
    /// Every user-role self other than the key that ever asserted it.
    selves: Vec<RosterHistory>,
}

/// The directory's facts about a set of keys. A key not in the set is its own
/// person ([`KeySelves::default`] is therefore the per-key count).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySelves {
    keys: BTreeMap<String, KeyFacts>,
}

/// The empty [`KeySelves`]: every key its own person.
pub static NO_KEY_SELVES: KeySelves = KeySelves {
    keys: BTreeMap::new(),
};

impl KeySelves {
    /// Read the facts of `keys`.
    ///
    /// # Errors
    ///
    /// The directory's.
    pub async fn read<D>(dir: &D, keys: Vec<String>) -> Result<Self, Error>
    where
        D: FederationDirectory + ?Sized,
    {
        let mut out = Self::default();
        out.add(dir, keys).await?;
        Ok(out)
    }

    /// Read the facts of each of `keys` not already held.
    ///
    /// # Errors
    ///
    /// The directory's.
    pub async fn add<D>(&mut self, dir: &D, keys: Vec<String>) -> Result<(), Error>
    where
        D: FederationDirectory + ?Sized,
    {
        for key in keys {
            if self.keys.contains_key(&key) {
                continue;
            }
            let facts = key_facts(dir, &key).await?;
            self.keys.entry(key).or_insert(facts);
        }
        Ok(())
    }

    /// Fixture: each `(self, device, left)` a user-role device of the self
    /// from the year 2000, evicted in 2001 when `left`. Read at a later
    /// instant.
    #[cfg(test)]
    pub(crate) fn of_devices(devices: &[(&str, &str, bool)]) -> Self {
        let year = |y: i32| chrono::TimeZone::with_ymd_and_hms(&Utc, y, 1, 1, 0, 0, 0).unwrap();
        Self {
            keys: devices
                .iter()
                .map(|(identity, device, left)| {
                    let facts = KeyFacts {
                        user: true,
                        evicted_since: None,
                        selves: vec![RosterHistory {
                            identity: (*identity).to_owned(),
                            asserted: vec![(year(2000), None)],
                            revocations: left.then(|| year(2001)).into_iter().collect(),
                        }],
                    };
                    ((*device).to_owned(), facts)
                })
                .collect(),
        }
    }

    /// Does this hold `key`?
    #[must_use]
    pub fn holds(&self, key: &str) -> bool {
        self.keys.contains_key(key)
    }

    /// The answers at `at`.
    #[must_use]
    pub fn at(&self, at: DateTime<Utc>) -> PersonsAt<'_> {
        PersonsAt {
            selves: self,
            more: None,
            at,
        }
    }

    /// The answers at `at`, reading `more` first (a caller's keys over a
    /// fold's shared set, without copying it).
    #[must_use]
    pub fn at_with<'a>(&'a self, more: &'a KeySelves, at: DateTime<Utc>) -> PersonsAt<'a> {
        PersonsAt {
            selves: self,
            more: Some(more),
            at,
        }
    }
}

async fn key_facts<D>(dir: &D, key: &str) -> Result<KeyFacts, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut asserted: BTreeMap<String, Vec<InstantInterval>> = BTreeMap::new();
    for h in dir
        .list_identity_occurrence_history_by_occurrence(key)
        .await?
    {
        asserted
            .entry(h.identity_key_id)
            .or_default()
            .push((h.asserted_at, h.valid_until));
    }
    for o in dir.list_identity_occurrences_by_occurrence_key(key).await? {
        asserted
            .entry(o.identity_key_id)
            .or_default()
            .push((o.asserted_at, o.valid_until));
    }
    asserted.remove(key);
    let mut selves = Vec::with_capacity(asserted.len());
    for (identity, asserted) in asserted {
        if !is_user_key(dir, &identity).await? {
            continue;
        }
        let revocations = dir
            .list_identity_occurrence_revocations_for(&identity)
            .await?
            .into_iter()
            .filter(|r| r.occurrence_key_id == key)
            .map(|r| r.effective_at)
            .collect();
        selves.push(RosterHistory {
            identity,
            asserted,
            revocations,
        });
    }
    Ok(KeyFacts {
        user: is_user_key(dir, key).await?,
        evicted_since: genesis_evicted_since(dir, key).await?,
        selves,
    })
}

/// [`KeySelves`] at one instant. `Copy`: it is two references and a time.
#[derive(Debug, Clone, Copy)]
pub struct PersonsAt<'a> {
    selves: &'a KeySelves,
    more: Option<&'a KeySelves>,
    at: DateTime<Utc>,
}

impl PersonsAt<'static> {
    /// The per-key count: every key its own person. The planes this cut does
    /// not move (a trust root's chain, a licence's quorum) ask this.
    #[must_use]
    pub fn each_key() -> Self {
        NO_KEY_SELVES.at(DateTime::<Utc>::MIN_UTC)
    }
}

impl<'a> PersonsAt<'a> {
    fn facts(&self, key: &str) -> Option<&'a KeyFacts> {
        self.more
            .and_then(|m| m.keys.get(key))
            .or_else(|| self.selves.keys.get(key))
    }

    /// The selves whose roster holds the key at this instant.
    fn live(&self, facts: &'a KeyFacts) -> Vec<&'a str> {
        if !facts.user {
            return Vec::new();
        }
        facts
            .selves
            .iter()
            .filter(|s| roster_assertion_live(&s.asserted, &s.revocations, self.at))
            .map(|s| s.identity.as_str())
            .collect()
    }

    /// The selves that had asserted the key by this instant.
    fn former(&self, facts: &'a KeyFacts) -> BTreeSet<&'a str> {
        if !facts.user {
            return BTreeSet::new();
        }
        facts
            .selves
            .iter()
            .filter(|s| s.asserted.iter().any(|(asserted, _)| *asserted <= self.at))
            .map(|s| s.identity.as_str())
            .collect()
    }

    /// The person whose seat this key's is. See the module docs.
    #[must_use]
    pub fn seat_person<'k>(&self, key: &'k str) -> &'k str
    where
        'a: 'k,
    {
        let Some(facts) = self.facts(key) else {
            return key;
        };
        match self.live(facts).as_slice() {
            [only] => only,
            [] => match self
                .former(facts)
                .into_iter()
                .collect::<Vec<_>>()
                .as_slice()
            {
                [only] => only,
                _ => key,
            },
            _ => key,
        }
    }

    /// The person this key's signature speaks for, or `None`: the key has
    /// left its self, or it sits on two rosters. See the module docs.
    #[must_use]
    pub fn voice<'k>(&self, key: &'k str) -> Option<&'k str>
    where
        'a: 'k,
    {
        let Some(facts) = self.facts(key) else {
            return Some(key);
        };
        match self.live(facts).as_slice() {
            [only] => Some(only),
            [] => {
                let evicted = facts.evicted_since.is_some_and(|since| since <= self.at);
                (!evicted && self.former(facts).is_empty()).then_some(key)
            }
            _ => None,
        }
    }

    /// The distinct persons seated on `roster`.
    #[must_use]
    pub fn seated<'k>(&self, roster: &'k [String]) -> BTreeSet<&'k str>
    where
        'a: 'k,
    {
        roster.iter().map(|k| self.seat_person(k)).collect()
    }

    /// Does `key` speak for a person seated on `roster`?
    #[must_use]
    pub fn speaks_for_a_seat(&self, key: &str, roster: &[String]) -> bool {
        self.voice(key)
            .is_some_and(|person| roster.iter().any(|k| self.seat_person(k) == person))
    }

    /// Are these two keys one person's?
    #[must_use]
    pub fn same_person(&self, a: &str, b: &str) -> bool {
        self.seat_person(a) == self.seat_person(b)
    }

    /// The keys of `candidates` whose signature counts toward `roster`: its
    /// seats, and any other key of a seated person (a second device).
    #[must_use]
    pub fn roster_with_devices<'k, I>(&self, roster: &[String], candidates: I) -> Vec<String>
    where
        I: IntoIterator<Item = &'k str>,
    {
        let mut out = roster.to_vec();
        out.extend(
            candidates
                .into_iter()
                .filter(|k| !roster.iter().any(|seat| seat == k))
                .filter(|k| self.speaks_for_a_seat(k, roster))
                .map(str::to_owned),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    fn device(identity: &str, asserted: i64, revoked: Option<i64>) -> RosterHistory {
        RosterHistory {
            identity: identity.to_owned(),
            asserted: vec![(t(asserted), None)],
            revocations: revoked.map(t).into_iter().collect(),
        }
    }

    fn selves(keys: Vec<(&str, KeyFacts)>) -> KeySelves {
        KeySelves {
            keys: keys.into_iter().map(|(k, f)| (k.to_owned(), f)).collect(),
        }
    }

    fn user(selves: Vec<RosterHistory>) -> KeyFacts {
        KeyFacts {
            user: true,
            evicted_since: None,
            selves,
        }
    }

    /// I1525: the answers a device moves through over its life.
    #[test]
    fn a_devices_person_follows_its_roster() {
        let s = selves(vec![("d", user(vec![device("f", 10, Some(20))]))]);
        // Before it joined, it stood alone.
        assert_eq!(s.at(t(5)).voice("d"), Some("d"));
        assert_eq!(s.at(t(5)).seat_person("d"), "d");
        // Live: it speaks for the self, and is the self's seat.
        assert_eq!(s.at(t(15)).voice("d"), Some("f"));
        assert_eq!(s.at(t(15)).seat_person("d"), "f");
        // Evicted: no voice, and the seat stays the person's.
        assert_eq!(s.at(t(25)).voice("d"), None);
        assert_eq!(s.at(t(25)).seat_person("d"), "f");
    }

    /// An expired assertion is a left self, the same as an eviction.
    #[test]
    fn an_expired_device_has_no_voice() {
        let mut h = device("f", 10, None);
        h.asserted[0].1 = Some(t(20));
        let s = selves(vec![("d", user(vec![h]))]);
        assert_eq!(s.at(t(15)).voice("d"), Some("f"));
        assert_eq!(s.at(t(25)).voice("d"), None);
    }

    /// An evicted genesis key speaks for nobody; its string still names the
    /// self, so the seat stands.
    #[test]
    fn an_evicted_genesis_key_has_no_voice() {
        let mut f = user(Vec::new());
        f.evicted_since = Some(t(20));
        let s = selves(vec![("f", f)]);
        assert_eq!(s.at(t(15)).voice("f"), Some("f"));
        assert_eq!(s.at(t(25)).voice("f"), None);
        assert_eq!(s.at(t(25)).seat_person("f"), "f");
    }

    /// A key live on two rosters names no one person: voiceless, never two
    /// voices.
    #[test]
    fn a_key_on_two_rosters_has_no_voice() {
        let s = selves(vec![(
            "d",
            user(vec![device("f", 10, None), device("g", 10, None)]),
        )]);
        assert_eq!(s.at(t(15)).voice("d"), None);
        assert_eq!(s.at(t(15)).seat_person("d"), "d");
    }

    /// A role that is on no self roster keeps its own voice, whatever
    /// occurrence history it carries (an agent or a node).
    #[test]
    fn a_non_user_key_is_its_own_voice() {
        let mut facts = user(vec![device("f", 10, None)]);
        facts.user = false;
        let s = selves(vec![("agent", facts)]);
        assert_eq!(s.at(t(15)).voice("agent"), Some("agent"));
        assert_eq!(s.at(t(15)).seat_person("agent"), "agent");
    }

    /// A key the set does not hold is its own person; the per-key count is
    /// the empty set.
    #[test]
    fn each_key_is_its_own_person() {
        let p = PersonsAt::each_key();
        assert_eq!(p.voice("x"), Some("x"));
        assert!(!p.same_person("x", "y"));
    }

    /// The caller's keys read over the shared set.
    #[test]
    fn more_is_read_first() {
        let shared = selves(vec![("d", user(vec![device("f", 10, None)]))]);
        let more = selves(vec![("e", user(vec![device("f", 10, None)]))]);
        let at = t(15) + Duration::seconds(1);
        let p = shared.at_with(&more, at);
        assert!(p.same_person("d", "e"));
    }
}
