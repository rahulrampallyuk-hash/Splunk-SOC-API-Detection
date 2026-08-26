# AWS Console Login Detections

Detection rules developed against a live AWS CloudTrail → S3 → Splunk pipeline.
All rules were tested against real events generated in a controlled lab account.

Environment: Splunk Free 10.2.1, `index=main`, `sourcetype=aws:cloudtrail`

---

## 1. Root Account Compromise Pattern

Detects repeated authentication failures followed by a successful login on the
root account from the same source IP — the signature of a successful credential
attack rather than a user mistyping a password.

```spl
index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin userIdentity.type=Root
| eval real_time=_time
| bin _time span=1h
| eval outcome=if(errorMessage="Failed authentication","FAILED","SUCCESS")
| stats count(eval(outcome="FAILED")) AS failures,
        count(eval(outcome="SUCCESS")) AS successes,
        min(real_time) AS first_seen,
        max(real_time) AS last_seen
        BY _time, sourceIPAddress
| eval duration_mins=round((last_seen-first_seen)/60,1)
| where failures >= 3 AND successes >= 1
| eval severity="CRITICAL - possible root compromise"
| convert ctime(first_seen) ctime(last_seen)
| table first_seen, last_seen, sourceIPAddress, failures, successes, duration_mins, severity
```

**Why these thresholds.** Failures alone are low value — users mistype passwords.
The high-fidelity signal is failures *followed by* a success from the same source.
Three failures filters out single typos. One success is enough, because on the root
account a single successful login after repeated failures is worth investigating.

**Why root specifically.** AWS guidance is that the root account should be secured
with MFA and effectively never used for daily operations. Any root console activity
is anomalous by default, which makes the false positive cost low.

**Known limitations.**
- An attacker who succeeds on the first attempt produces no failures and is not detected.
- Grouping by source IP alone means an attacker rotating IPs falls below the threshold.
- The one-hour window is arbitrary. A slower attack spanning several hours is split
  across buckets and may not trip the rule.

**Development note.** The first version of this rule grouped only by `sourceIPAddress`
with no time window. It produced a single alert with a duration of 17,257 minutes —
twelve days of unrelated activity collapsed into one "incident." A second bug then
appeared: `bin _time` overwrites `_time`, so `min(_time)` and `max(_time)` returned
the same bucket boundary and every duration read 0.0. The real timestamp has to be
preserved before binning.

---

## 2. Credential Attack Pattern Classifier

Distinguishes brute force, password spraying, and credential stuffing using the
ratio of attempts to distinct accounts, rather than a flat failure count.

```spl
index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin errorMessage="Failed authentication"
| bin _time span=30m
| stats dc(userIdentity.userName) AS unique_users,
        count AS total_attempts,
        values(userIdentity.userName) AS targeted_accounts
        BY _time, sourceIPAddress
| eval attempts_per_user=round(total_attempts/unique_users,1)
| eval pattern=case(
    unique_users >= 3 AND attempts_per_user <= 3, "PASSWORD SPRAYING",
    unique_users <= 2 AND attempts_per_user >= 5, "BRUTE FORCE",
    unique_users >= 3 AND attempts_per_user >= 5, "CREDENTIAL STUFFING - broad and deep",
    1=1, "Low confidence")
| where unique_users >= 3 OR attempts_per_user >= 5
| table _time, sourceIPAddress, unique_users, total_attempts, attempts_per_user, pattern, targeted_accounts
```

**Why this exists.** A previous brute force rule counted failures per source IP and
triggered on three or more within five minutes. That rule catches an attacker
hammering one account, but misses password spraying entirely — spraying spreads one
or two attempts across many accounts so no single account approaches the threshold.
Counting distinct usernames per source is the fix.

**Why the ratio matters.** An early version only checked `unique_users >= 3` and
labelled every result as spraying. That was wrong: a brute force attack against four
accounts would also match. Spraying is defined by being *shallow* as well as broad,
so the rule has to bound `attempts_per_user` from above, not just count accounts.

**Known limitations.**
- An attacker who distributes attempts across multiple source IPs defeats the
  grouping entirely.
- The 30-minute window misses genuinely low-and-slow campaigns spread over days.
- CloudTrail omits `userName` for root identities, so root events are silently
  excluded from any rule that groups by username (see below).

---

## 3. Field-level finding: root identities have no userName

CloudTrail does not populate `userIdentity.userName` for root. Root events carry
`userIdentity.type=Root` and an ARN ending in `:root` instead.

Any detection rule that groups or aggregates by `userIdentity.userName` will
therefore drop root events without error and without warning — silently excluding
the most privileged identity in the account.

```spl
index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin errorMessage="Failed authentication" NOT userIdentity.userName=*
| table _time, userIdentity.type, userIdentity.arn, sourceIPAddress
```

This is why root needs its own rule rather than being folded into a general
authentication-failure detection.

---

## 4. Pipeline measurements

Two properties of the data source that constrain what any rule built on it can do.

### Ingestion lag

```spl
index=main sourcetype=aws:cloudtrail earliest=-2h
| eval delay_mins=round((_indextime-_time)/60,1)
| stats avg(delay_mins) AS avg_delay, max(delay_mins) AS worst_delay
```

Measured on this pipeline: **14.4 minutes average, 65.9 minutes worst case.**

CloudTrail batches delivery to S3, and the Splunk S3 input polls on its own interval.
Two queues in series. The consequence is that detection latency is bounded by the
pipeline, not the rule — a perfectly tuned rule can still only alert on something
that happened up to an hour ago. Closing that gap means moving off S3 polling to
CloudWatch Logs subscriptions or Kinesis Firehose.

### Event amplification

```spl
index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin errorMessage="Failed authentication"
| bin _time span=30m AS window
| eval minute=strftime(_time,"%Y-%m-%d %H:%M")
| stats dc(userIdentity.userName) AS unique_users,
        dc(minute) AS distinct_minutes,
        count AS raw_events
        BY window, sourceIPAddress
| eval amplification=round(raw_events/distinct_minutes,1)
| table window, sourceIPAddress, unique_users, distinct_minutes, raw_events, amplification
```

Across six windows in this dataset the ratio of raw events to distinct active minutes
ranged from **1.0 to 6.4**. In one test session, 8 deliberate failed logins produced
51
