use super::*;
use std::collections::{BTreeMap, BTreeSet};

const DAY: u64 = 86_400_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScorecardRequest {
    pub from: u64,
    pub to_exclusive: u64,
    pub as_of: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metric {
    pub id: String,
    pub value: Option<serde_json::Value>,
    pub numerator: Option<usize>,
    pub denominator: Option<usize>,
    pub mature_cohort_size: usize,
    pub pending: usize,
    pub lost: usize,
    pub unknown: usize,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scorecard {
    pub definition_version: u32,
    pub window: ScorecardRequest,
    pub window_complete: bool,
    pub snapshot_sha256: String,
    pub visible_observations: usize,
    pub excluded_synthetic_seed: usize,
    pub unknown_audience_binding: usize,
    pub conflicting_events: usize,
    pub metrics: Vec<Metric>,
    pub coverage_scope: String,
}

#[derive(Clone)]
struct Journey<'a> {
    rows: Vec<&'a RecordedObservation>,
    start: &'a RecordedObservation,
    activation: Option<&'a RecordedObservation>,
    inspected: bool,
    selected: bool,
    conflict: bool,
}

fn checked(value: &Option<Evidence>) -> bool {
    value.as_ref().is_some_and(Evidence::checked)
}
fn weekly_window(request: &ScorecardRequest) -> bool {
    request.from % DAY == 0
        && (request.from / DAY + 3) % 7 == 0
        && request.from.checked_add(7 * DAY) == Some(request.to_exclusive)
}
fn in_window(time: u64, request: &ScorecardRequest) -> bool {
    time >= request.from && time < request.to_exclusive
}
fn elapsed(start: u64, end: u64, duration: u64) -> bool {
    end.checked_sub(start).is_some_and(|n| n < duration)
}
fn mature(start: u64, as_of: u64, duration: u64) -> bool {
    start.checked_add(duration).is_some_and(|n| n <= as_of)
}
fn exact_protocol(a: &ObservationEvent, b: &ObservationEvent) -> bool {
    a.protocol_digest.is_some()
        && a.protocol_digest == b.protocol_digest
        && match (&a.release, &b.release) {
            (Some(left), Some(right)) => left == right,
            (None, None) => a.protocol_ref.is_some() && a.protocol_ref == b.protocol_ref,
            _ => false,
        }
}

fn journeys<'a>(rows: &[&'a RecordedObservation]) -> Vec<Journey<'a>> {
    let mut groups = BTreeMap::<&str, Vec<&RecordedObservation>>::new();
    for row in rows {
        groups.entry(&row.event.journey_id).or_default().push(row);
    }
    let mut result = Vec::new();
    for group in groups.values_mut() {
        group.sort_by_key(|r| (r.event.occurred_at, r.observed_at));
        let Some(start) = group
            .iter()
            .find(|r| r.event.event_type == EventType::QualifiedStart && r.event.external())
        else {
            continue;
        };
        let start = *start;
        let principal = start.event.principal_ref.as_deref();
        let conflict = group.iter().any(|r| {
            r.event
                .principal_ref
                .as_deref()
                .is_some_and(|p| Some(p) != principal)
                || r.event
                    .task_ref
                    .as_deref()
                    .is_some_and(|t| Some(t) != start.event.task_ref.as_deref())
        });
        let selections: Vec<_> = group
            .iter()
            .filter(|r| {
                r.event.event_type == EventType::AdoptionSelected
                    && r.event.external()
                    && r.event.outcome == Outcome::Pass
            })
            .copied()
            .collect();
        let selection = selections.first().copied();
        let first_touch = group
            .iter()
            .filter(|r| {
                r.event.external()
                    && r.event.source_ref.is_some()
                    && checked(&r.event.source_evidence)
                    && r.event
                        .source_channel
                        .is_some_and(|c| c != Channel::Unknown)
                    && r.event.occurred_at >= start.event.occurred_at.saturating_sub(30 * DAY)
                    && r.event.occurred_at <= start.event.occurred_at
            })
            .map(|r| r.event.occurred_at)
            .min();
        let sources: BTreeSet<_> = group
            .iter()
            .filter(|r| {
                Some(r.event.occurred_at) == first_touch && checked(&r.event.source_evidence)
            })
            .map(|r| {
                (
                    r.event.source_ref.as_deref(),
                    r.event.source_channel.map(|c| format!("{c:?}")),
                )
            })
            .collect();
        let assignment_conflict = group.iter().any(|r| {
            r.event.variant_ref.is_some() && r.event.variant_ref != start.event.variant_ref
        });
        let conflict = conflict || sources.len() > 1 || assignment_conflict;
        let selection_conflict = selections.windows(2).any(|pair| {
            pair[0].event.release != pair[1].event.release
                || pair[0].event.protocol_ref != pair[1].event.protocol_ref
                || pair[0].event.instance_ref != pair[1].event.instance_ref
                || pair[0].event.protocol_digest != pair[1].event.protocol_digest
                || pair[0].event.adoption_branch != pair[1].event.adoption_branch
        });
        let inspected = group.iter().any(|r| {
            r.event.event_type == EventType::ReleaseVerified
                && r.event.external()
                && r.event.outcome == Outcome::Pass
                && (r.event.release.is_some() || r.event.protocol_ref.is_some())
        });
        let selection_inspected = selection.is_some_and(|s| {
            group.iter().any(|r| {
                r.event.event_type == EventType::ReleaseVerified
                    && r.event.external()
                    && r.event.outcome == Outcome::Pass
                    && (r
                        .event
                        .release
                        .as_ref()
                        .is_some_and(|release| s.event.release.as_ref() == Some(release))
                        || r.event.release.is_none()
                            && s.event.release.is_none()
                            && exact_protocol(&r.event, &s.event))
                    && r.event.occurred_at <= s.event.occurred_at
            })
        });
        let selected = selection.is_some_and(|s| {
            selection_inspected
                && s.event.instance_ref.is_some()
                && s.event.protocol_digest.is_some()
                && checked(&s.event.association_evidence)
                && s.event.occurred_at >= start.event.occurred_at
                && s.event.adoption_branch.is_some()
        });
        let installed = selection.is_some_and(|s| match s.event.adoption_branch {
            Some(AdoptionBranch::ExistingInstall) => true,
            Some(AdoptionBranch::NewInstall) => group.iter().any(|r| {
                r.event.event_type == EventType::InstallAccepted
                    && r.event.external()
                    && r.event.outcome == Outcome::Pass
                    && checked(&r.event.signed_result_evidence)
                    && exact_protocol(&r.event, &s.event)
                    && r.event.instance_ref == s.event.instance_ref
                    && r.event.occurred_at >= s.event.occurred_at
            }),
            None => false,
        });
        let activation = if !conflict
            && !selection_conflict
            && selected
            && installed
            && start.event.task_ref.is_some()
            && start.event.acceptance_predicate_ref.is_some()
        {
            group
                .iter()
                .find(|r| {
                    let s = selection.unwrap();
                    r.event.event_type == EventType::TaskOutcomeVerified
                        && r.event.external()
                        && r.event.outcome == Outcome::Pass
                        && checked(&r.event.signed_result_evidence)
                        && r.event.task_ref == start.event.task_ref
                        && r.event.acceptance_predicate_ref == start.event.acceptance_predicate_ref
                        && exact_protocol(&r.event, &s.event)
                        && r.event.instance_ref == s.event.instance_ref
                        && r.event.occurred_at >= s.event.occurred_at
                        && (start.observed_at <= r.event.occurred_at
                            || checked(&start.event.enrollment_timing_evidence))
                })
                .copied()
        } else {
            None
        };
        result.push(Journey {
            rows: group.clone(),
            start,
            activation,
            inspected,
            selected,
            conflict: conflict || selection_conflict,
        });
    }
    result
}

fn coverage_through(journey: &Journey<'_>, end: u64) -> Coverage {
    if journey.rows.iter().any(|r| {
        r.event.coverage == Some(Coverage::Complete)
            && r.event.observation_end.is_some_and(|t| t >= end)
    }) {
        Coverage::Complete
    } else if journey
        .rows
        .iter()
        .any(|r| r.event.coverage == Some(Coverage::Lost))
    {
        Coverage::Lost
    } else {
        Coverage::Unknown
    }
}

fn primary_touch<'a>(journey: &Journey<'a>) -> Option<&'a RecordedObservation> {
    let at = journey.start.event.occurred_at;
    journey
        .rows
        .iter()
        .copied()
        .filter(|r| {
            r.event.external()
                && r.event.source_ref.is_some()
                && checked(&r.event.source_evidence)
                && r.event
                    .source_channel
                    .is_some_and(|c| c != Channel::Unknown)
                && r.event.occurred_at >= at.saturating_sub(30 * DAY)
                && r.event.occurred_at <= at
        })
        .min_by_key(|r| (r.event.occurred_at, r.observed_at))
}

fn ratio(
    id: &str,
    numerator: usize,
    denominator: usize,
    mature_size: usize,
    pending: usize,
    lost: usize,
    unknown: usize,
    details: serde_json::Value,
) -> Metric {
    Metric {
        id: id.into(),
        value: (denominator > 0).then(|| serde_json::json!(numerator as f64 / denominator as f64)),
        numerator: Some(numerator),
        denominator: Some(denominator),
        mature_cohort_size: mature_size,
        pending,
        lost,
        unknown,
        details,
    }
}

fn activation_cohort(
    id: &str,
    all: &[Journey<'_>],
    request: &ScorecardRequest,
    duration: u64,
) -> Metric {
    let mut principals = BTreeMap::<&str, Vec<&Journey<'_>>>::new();
    for journey in all {
        principals
            .entry(journey.start.event.principal_ref.as_deref().unwrap())
            .or_default()
            .push(journey);
    }
    let mut n = 0;
    let mut d = 0;
    let mut matured = 0;
    let mut pending = 0;
    let mut lost = 0;
    let mut unknown = 0;
    let mut observed_success = 0;
    let mut observed_failure = 0;
    let mut unresolved = 0;
    for group in principals.values() {
        let first = group
            .iter()
            .min_by_key(|j| j.start.event.occurred_at)
            .unwrap();
        let start = first.start.event.occurred_at;
        if !in_window(start, request) {
            continue;
        }
        if !mature(start, request.as_of, duration) {
            pending += 1;
            continue;
        }
        matured += 1;
        let success = group.iter().any(|j| {
            j.activation
                .is_some_and(|a| elapsed(start, a.event.occurred_at, duration))
        });
        if success {
            observed_success += 1
        } else if group.iter().any(|j| {
            j.rows.iter().any(|r| {
                r.event.external()
                    && r.event.event_type == EventType::TaskOutcomeVerified
                    && r.event.outcome == Outcome::Fail
                    && elapsed(start, r.event.occurred_at, duration)
            })
        }) {
            observed_failure += 1
        } else {
            unresolved += 1
        }
        let coverage = coverage_through(first, start + duration);
        if coverage == Coverage::Complete {
            d += 1;
            if success {
                n += 1
            }
        } else if coverage == Coverage::Lost {
            lost += 1
        } else {
            unknown += 1
        }
    }
    ratio(
        id,
        n,
        d,
        matured,
        pending,
        lost,
        unknown,
        serde_json::json!({
            "unit":"unique_external_principals","observed_success_all_mature_starts":observed_success,
            "conservative_observed_success_rate":if matured>0 {Some(observed_success as f64/matured as f64)} else {None},
            "window_ms":duration,"observed_business_fail":observed_failure,"unresolved_mature_starts":unresolved
        }),
    )
}

fn funnel(id: &str, all: &[Journey<'_>], request: &ScorecardRequest, duration: u64) -> Metric {
    let eligible: Vec<_> = all
        .iter()
        .filter(|j| in_window(j.start.event.occurred_at, request))
        .collect();
    let matured: Vec<_> = eligible
        .iter()
        .filter(|j| mature(j.start.event.occurred_at, request.as_of, duration))
        .copied()
        .collect();
    let complete: Vec<_> = matured
        .iter()
        .filter(|j| coverage_through(j, j.start.event.occurred_at + duration) == Coverage::Complete)
        .copied()
        .collect();
    let inspected = complete
        .iter()
        .filter(|j| {
            j.inspected
                && j.rows.iter().any(|r| {
                    r.event.event_type == EventType::ReleaseVerified
                        && r.event.external()
                        && r.event.outcome == Outcome::Pass
                        && elapsed(j.start.event.occurred_at, r.event.occurred_at, duration)
                })
        })
        .count();
    let selected = complete
        .iter()
        .filter(|j| {
            j.selected
                && j.rows.iter().any(|r| {
                    r.event.event_type == EventType::AdoptionSelected
                        && r.event.external()
                        && r.event.outcome == Outcome::Pass
                        && elapsed(j.start.event.occurred_at, r.event.occurred_at, duration)
                })
        })
        .count();
    let useful = complete
        .iter()
        .filter(|j| {
            j.activation
                .is_some_and(|a| elapsed(j.start.event.occurred_at, a.event.occurred_at, duration))
        })
        .count();
    let lost = matured
        .iter()
        .filter(|j| coverage_through(j, j.start.event.occurred_at + duration) == Coverage::Lost)
        .count();
    ratio(
        id,
        useful,
        complete.len(),
        matured.len(),
        eligible.len() - matured.len(),
        lost,
        matured.len() - complete.len() - lost,
        serde_json::json!({"unit":"joined_journeys","verified_inspection":inspected,"deliberate_selection":selected,
            "new_install_selection":complete.iter().filter(|j| j.rows.iter().any(|r| r.event.event_type==EventType::AdoptionSelected && r.event.adoption_branch==Some(AdoptionBranch::NewInstall))).count(),
            "existing_install_selection":complete.iter().filter(|j| j.rows.iter().any(|r| r.event.event_type==EventType::AdoptionSelected && r.event.adoption_branch==Some(AdoptionBranch::ExistingInstall))).count()}),
    )
}

fn first_activations<'a>(all: &[Journey<'a>]) -> BTreeMap<&'a str, &'a RecordedObservation> {
    let mut first = BTreeMap::<&str, &RecordedObservation>::new();
    for journey in all {
        if let Some(result) = journey.activation {
            let principal = journey.start.event.principal_ref.as_deref().unwrap();
            if first
                .get(principal)
                .is_none_or(|old| result.event.occurred_at < old.event.occurred_at)
            {
                first.insert(principal, result);
            }
        }
    }
    first
}

fn cost_metric(id: &str, all: &[Journey<'_>], request: &ScorecardRequest, duration: u64) -> Metric {
    let mut groups = BTreeMap::<&str, Vec<&Journey<'_>>>::new();
    for j in all {
        groups
            .entry(j.start.event.principal_ref.as_deref().unwrap())
            .or_default()
            .push(j);
    }
    let mut times = Vec::<u64>::new();
    let mut mature_size = 0;
    let mut pending = 0;
    let mut lost = 0;
    let mut unknown = 0;
    let mut total_cost = 0u128;
    let mut cost_unit: Option<&str> = None;
    let mut complete_cost = true;
    let mut attempt_count = 0;
    let mut active_ms = 0u128;
    let mut wait_ms = 0u128;
    let mut calls = 0u128;
    let mut tokens = 0u128;
    let mut active_complete = true;
    let mut wait_complete = true;
    let mut calls_complete = true;
    let mut tokens_complete = true;
    for group in groups.values() {
        let first = group
            .iter()
            .min_by_key(|j| j.start.event.occurred_at)
            .unwrap();
        let start = first.start.event.occurred_at;
        if !in_window(start, request) {
            continue;
        }
        if !mature(start, request.as_of, duration) {
            pending += 1;
            continue;
        }
        mature_size += 1;
        match coverage_through(first, start + duration) {
            Coverage::Complete => (),
            Coverage::Lost => {
                lost += 1;
                complete_cost = false;
                active_complete = false;
                wait_complete = false;
                calls_complete = false;
                tokens_complete = false
            }
            Coverage::Unknown => {
                unknown += 1;
                complete_cost = false;
                active_complete = false;
                wait_complete = false;
                calls_complete = false;
                tokens_complete = false
            }
        }
        if let Some(result) = group
            .iter()
            .filter_map(|j| j.activation)
            .filter(|a| elapsed(start, a.event.occurred_at, duration))
            .min_by_key(|a| a.event.occurred_at)
        {
            times.push(result.event.occurred_at - start);
        }
        let mut attempts = BTreeMap::<&str, Vec<&RecordedObservation>>::new();
        for j in group {
            for row in &j.rows {
                if elapsed(start, row.event.occurred_at, duration) {
                    attempts.entry(&row.event.attempt_id).or_default().push(row);
                }
            }
        }
        for observations in attempts.values() {
            attempt_count += 1;
            let finished: Vec<_> = observations
                .iter()
                .filter(|r| r.event.event_type == EventType::AttemptFinished && r.event.external())
                .collect();
            let Some(last) = finished.last() else {
                complete_cost = false;
                active_complete = false;
                wait_complete = false;
                calls_complete = false;
                tokens_complete = false;
                continue;
            };
            match last.event.active_execution_ms {
                Some(n) => active_ms += u128::from(n),
                None => active_complete = false,
            }
            match last.event.external_wait_ms {
                Some(n) => wait_ms += u128::from(n),
                None => wait_complete = false,
            }
            match last.event.calls {
                Some(n) => calls += u128::from(n),
                None => calls_complete = false,
            }
            match last.event.tokens {
                Some(n) => tokens += u128::from(n),
                None => tokens_complete = false,
            }
            let Some(cost) = last.event.cost.as_ref() else {
                complete_cost = false;
                continue;
            };
            if finished.iter().any(|r| r.event.cost.as_ref() != Some(cost)) {
                complete_cost = false;
                continue;
            }
            if cost_unit.is_some_and(|unit| unit != cost.unit) {
                complete_cost = false;
                continue;
            }
            cost_unit = Some(&cost.unit);
            total_cost += u128::from(cost.amount_microunits);
        }
    }
    times.sort_unstable();
    let quantile = |percent: usize| -> Option<u64> {
        if times.is_empty() {
            None
        } else {
            Some(times[(times.len() * percent).div_ceil(100).saturating_sub(1)])
        }
    };
    let per_activation = if complete_cost && !times.is_empty() && attempt_count > 0 {
        Some(total_cost as f64 / times.len() as f64)
    } else {
        None
    };
    let measured = |total: u128, complete: bool| {
        if complete && attempt_count > 0 {
            u64::try_from(total).ok().filter(|n| *n <= MAX_SAFE_INTEGER)
        } else {
            None
        }
    };
    Metric {
        id: id.into(),
        value: (!times.is_empty()).then(|| {
            serde_json::json!({"p50_wall_ms":quantile(50),"p90_wall_ms":quantile(90),
        "cost_microunits_per_activation":per_activation,"cost_unit":cost_unit})
        }),
        numerator: Some(times.len()),
        denominator: Some(mature_size),
        mature_cohort_size: mature_size,
        pending,
        lost,
        unknown,
        details: serde_json::json!({"unit":"mature_principal_start_cohort",
            "all_attempts_in_fixed_window":attempt_count,"complete_cost_coverage":complete_cost && attempt_count>0,
            "active_execution_ms":measured(active_ms,active_complete),
            "external_wait_ms":measured(wait_ms,wait_complete),
            "measured_calls":measured(calls,calls_complete),
            "measured_tokens":measured(tokens,tokens_complete),"partial_cost_estimate":null}),
    }
}

fn retention(
    id: &str,
    all: &[Journey<'_>],
    request: &ScorecardRequest,
    lower: u64,
    upper: u64,
) -> Metric {
    let first = first_activations(all);
    let mut n = 0;
    let mut d = 0;
    let mut mature_size = 0;
    let mut pending = 0;
    let mut lost = 0;
    let mut unknown = 0;
    for (principal, activation) in &first {
        let at = activation.event.occurred_at;
        if !in_window(at, request) {
            continue;
        }
        if !mature(at, request.as_of, upper) {
            pending += 1;
            continue;
        }
        mature_size += 1;
        let group: Vec<_> = all
            .iter()
            .filter(|j| j.start.event.principal_ref.as_deref() == Some(principal))
            .collect();
        let coverage = group
            .iter()
            .find(|j| {
                j.activation
                    .is_some_and(|a| a.event.event_id == activation.event.event_id)
            })
            .map(|j| coverage_through(j, at + upper))
            .unwrap_or(Coverage::Unknown);
        if coverage == Coverage::Lost {
            lost += 1;
            continue;
        }
        if coverage != Coverage::Complete {
            unknown += 1;
            continue;
        }
        d += 1;
        let repeat = group.iter().filter_map(|j| j.activation).any(|a| {
            let delta = a.event.occurred_at.checked_sub(at);
            delta.is_some_and(|t| t >= lower && t < upper && t > 0)
                && a.event.task_ref != activation.event.task_ref
                && a.event.acceptance_predicate_ref != activation.event.acceptance_predicate_ref
        });
        if repeat {
            n += 1
        }
    }
    ratio(
        id,
        n,
        d,
        mature_size,
        pending,
        lost,
        unknown,
        serde_json::json!({"unit":"activated_external_principals",
        "repeat_from_ms":lower,"repeat_to_exclusive_ms":upper,"distinct_task_and_acceptance_required":true}),
    )
}

fn publication(rows: &[&RecordedObservation], request: &ScorecardRequest) -> Metric {
    let mut requests = BTreeMap::<&str, &RecordedObservation>::new();
    for row in rows
        .iter()
        .filter(|r| r.event.event_type == EventType::PublishRequested && r.event.external())
    {
        requests
            .entry(&row.event.journey_id)
            .and_modify(|old| {
                if row.event.occurred_at < old.event.occurred_at {
                    *old = row
                }
            })
            .or_insert(row);
    }
    let mut n = 0;
    let mut d = 0;
    let mut mature_size = 0;
    let mut pending = 0;
    let mut lost = 0;
    let mut unknown = 0;
    let mut receipt_count = 0;
    let mut visibility_count = 0;
    for first in requests.values() {
        let at = first.event.occurred_at;
        if !in_window(at, request) {
            continue;
        }
        if !mature(at, request.as_of, DAY) {
            pending += 1;
            continue;
        }
        mature_size += 1;
        let group: Vec<_> = rows
            .iter()
            .copied()
            .filter(|r| {
                r.event.journey_id == first.event.journey_id
                    && r.event.principal_ref == first.event.principal_ref
            })
            .collect();
        let complete = group.iter().any(|r| {
            r.event.coverage == Some(Coverage::Complete)
                && r.event.observation_end.is_some_and(|end| end >= at + DAY)
        });
        if !complete {
            if group
                .iter()
                .any(|r| r.event.coverage == Some(Coverage::Lost))
            {
                lost += 1
            } else {
                unknown += 1
            }
            continue;
        }
        let Some(release) = &first.event.release else {
            unknown += 1;
            continue;
        };
        if release.namespace.is_none() {
            unknown += 1;
            continue;
        }
        let conflicting = group
            .iter()
            .filter_map(|r| r.event.release.as_ref())
            .any(|other| {
                other.catalog_origin == release.catalog_origin
                    && other.namespace == release.namespace
                    && other.package_id == release.package_id
                    && other.version == release.version
                    && other.bundle_digest != release.bundle_digest
            });
        if conflicting {
            unknown += 1;
            continue;
        }
        d += 1;
        let receipt = group.iter().any(|r| {
            r.event.event_type == EventType::PublishAccepted
                && r.event.external()
                && r.event.outcome == Outcome::Pass
                && checked(&r.event.signed_result_evidence)
                && r.event.release.as_ref() == Some(release)
                && elapsed(at, r.event.occurred_at, DAY)
        });
        let visible = group.iter().any(|r| {
            r.event.event_type == EventType::ReleaseVisible
                && r.event.external()
                && r.event.outcome == Outcome::Pass
                && r.event.release.as_ref() == Some(release)
                && elapsed(at, r.event.occurred_at, DAY)
        });
        if receipt {
            receipt_count += 1
        }
        if visible {
            visibility_count += 1
        }
        if receipt && visible {
            n += 1
        }
    }
    ratio(
        "ACQ-06",
        n,
        d,
        mature_size,
        pending,
        lost,
        unknown,
        serde_json::json!({"unit":"authorized_publication_journeys",
        "signed_receipt":receipt_count,"exact_public_visibility":visibility_count,"window_ms":DAY}),
    )
}

fn share(
    id: &str,
    rows: &[&RecordedObservation],
    all: &[Journey<'_>],
    request: &ScorecardRequest,
    duration: u64,
) -> Metric {
    let mut recipients = BTreeMap::<&str, &RecordedObservation>::new();
    for handoff in rows.iter().filter(|r| {
        r.event.event_type == EventType::ShareReferenceObserved
            && r.event.external()
            && r.event.outcome == Outcome::Pass
            && r.event.source_ref.is_some()
            && (r.event.release.is_some() || r.event.protocol_ref.is_some())
            && r.event.referrer_audience_class == Some(Audience::ExternalEvidenced)
            && checked(&r.event.referrer_binding)
            && checked(&r.event.distinct_controller_evidence)
            && r.event.referrer_principal_ref.is_some()
            && r.event.referrer_principal_ref != r.event.principal_ref
    }) {
        let recipient = handoff.event.principal_ref.as_deref().unwrap();
        recipients
            .entry(recipient)
            .and_modify(|old| {
                if handoff.event.occurred_at < old.event.occurred_at {
                    *old = handoff
                }
            })
            .or_insert(handoff);
    }
    let mut n = 0;
    let mut d = 0;
    let mut mature_size = 0;
    let mut pending = 0;
    let mut lost = 0;
    let mut unknown = 0;
    let mut sharers = BTreeSet::new();
    for (principal, handoff) in recipients {
        let at = handoff.event.occurred_at;
        if !in_window(at, request) {
            continue;
        }
        if !mature(at, request.as_of, duration) {
            pending += 1;
            continue;
        }
        mature_size += 1;
        let coverage: Vec<_> = rows
            .iter()
            .filter(|r| {
                r.event.journey_id == handoff.event.journey_id
                    && r.event.principal_ref == handoff.event.principal_ref
            })
            .collect();
        if !coverage.iter().any(|r| {
            r.event.coverage == Some(Coverage::Complete)
                && r.event
                    .observation_end
                    .is_some_and(|end| end >= at + duration)
        }) {
            if coverage
                .iter()
                .any(|r| r.event.coverage == Some(Coverage::Lost))
            {
                lost += 1
            } else {
                unknown += 1
            }
            continue;
        }
        d += 1;
        sharers.insert(handoff.event.referrer_principal_ref.as_deref().unwrap());
        let first = all
            .iter()
            .filter(|j| j.start.event.principal_ref.as_deref() == Some(principal))
            .min_by_key(|j| j.start.event.occurred_at);
        if let Some(first) = first {
            if elapsed(at, first.start.event.occurred_at, duration)
                && primary_touch(first).is_some_and(|touch| {
                    touch.event.source_channel == Some(Channel::CanonicalShare)
                        && touch.event.source_ref == handoff.event.source_ref
                })
                && first.activation.is_some_and(|a| {
                    elapsed(at, a.event.occurred_at, duration)
                        && a.event.newness == Newness::ProvedNew
                        && a.event.newness_evidence.checked()
                        && (a
                            .event
                            .release
                            .as_ref()
                            .is_some_and(|release| handoff.event.release.as_ref() == Some(release))
                            || a.event.release.is_none()
                                && handoff.event.release.is_none()
                                && exact_protocol(&a.event, &handoff.event))
                })
            {
                n += 1
            }
        }
    }
    ratio(
        id,
        n,
        d,
        mature_size,
        pending,
        lost,
        unknown,
        serde_json::json!({"unit":"unique_evidenced_recipient_handoffs",
        "sharing_principals_same_mature_cohort":sharers.len(),
        "activated_recipients_per_sharing_principal":if sharers.is_empty(){None}else{Some(n as f64/sharers.len() as f64)},
        "nonstarting_recipients_retained":true,"window_ms":duration}),
    )
}

fn supply(
    rows: &[&RecordedObservation],
    all: &[Journey<'_>],
    request: &ScorecardRequest,
) -> Metric {
    let mut publishers = BTreeSet::new();
    let mut unknown = 0;
    for result in all
        .iter()
        .filter_map(|j| j.activation)
        .filter(|a| in_window(a.event.occurred_at, request))
    {
        let Some(publisher) = result.event.publisher_principal_ref.as_deref() else {
            unknown += 1;
            continue;
        };
        if Some(publisher) == result.event.principal_ref.as_deref()
            || !checked(&result.event.distinct_controller_evidence)
        {
            unknown += 1;
            continue;
        }
        let selected_release = if checked(&result.event.lineage_evidence) {
            result
                .event
                .source_release
                .as_ref()
                .or(result.event.release.as_ref())
        } else {
            result.event.release.as_ref()
        };
        let published = rows.iter().any(|r| {
            r.event.event_type == EventType::PublishAccepted
                && r.event.external()
                && r.event.outcome == Outcome::Pass
                && checked(&r.event.signed_result_evidence)
                && r.event.principal_ref.as_deref() == Some(publisher)
                && r.event.release.as_ref() == selected_release
                && r.event.release.is_some()
                && r.event.occurred_at <= result.event.occurred_at
        });
        let visible = rows.iter().any(|r| {
            r.event.event_type == EventType::ReleaseVisible
                && r.event.external()
                && r.event.outcome == Outcome::Pass
                && r.event.principal_ref.as_deref() == Some(publisher)
                && r.event.release.as_ref() == selected_release
                && r.event.occurred_at <= result.event.occurred_at
        });
        if published && visible {
            publishers.insert(publisher);
        } else {
            unknown += 1
        }
    }
    Metric {
        id: "ACQ-08".into(),
        value: rows
            .iter()
            .any(|r| r.event.external())
            .then(|| serde_json::json!(publishers.len())),
        numerator: Some(publishers.len()),
        denominator: None,
        mature_cohort_size: 0,
        pending: 0,
        lost: 0,
        unknown,
        details: serde_json::json!({"unit":"external_publishers_with_different_controller_use","derivative_volume_is_not_use":true}),
    }
}

fn agent_outcomes(rows: &[&RecordedObservation], request: &ScorecardRequest) -> Metric {
    let mut attempts = BTreeMap::<&str, &RecordedObservation>::new();
    for row in rows.iter().filter(|r| {
        r.event.event_type == EventType::AttemptFinished
            && r.event.external()
            && r.event.run_kind == Some(RunKind::NaturalAgent)
            && in_window(r.event.occurred_at, request)
    }) {
        attempts.insert(&row.event.attempt_id, row);
    }
    let first: Vec<_> = attempts
        .values()
        .filter(|r| r.event.attempt_class == AttemptClass::FirstAttempt)
        .copied()
        .collect();
    let recovered: Vec<_> = attempts
        .values()
        .filter(|r| r.event.attempt_class == AttemptClass::Recovery)
        .copied()
        .collect();
    let tally = |group: &[&RecordedObservation]| {
        serde_json::json!({
            "runs":group.len(),"business_pass":group.iter().filter(|r|r.event.outcome==Outcome::Pass).count(),
            "business_fail":group.iter().filter(|r|r.event.outcome==Outcome::Fail).count(),
            "business_unverified":group.iter().filter(|r|matches!(r.event.outcome,Outcome::Pending|Outcome::Unverified)).count(),
            "workflow_pass":group.iter().filter(|r|r.event.workflow_outcome==Some(Outcome::Pass)).count(),
            "workflow_fail":group.iter().filter(|r|r.event.workflow_outcome==Some(Outcome::Fail)).count(),
            "workflow_unverified":group.iter().filter(|r|!matches!(r.event.workflow_outcome,Some(Outcome::Pass|Outcome::Fail))).count(),
        })
    };
    Metric {
        id: "ACQ-09".into(),
        value: (!attempts.is_empty()).then(
            || serde_json::json!({"first_attempt":tally(&first),"recovery":tally(&recovered)}),
        ),
        numerator: None,
        denominator: Some(attempts.len()),
        mature_cohort_size: attempts.len(),
        pending: 0,
        lost: 0,
        unknown: attempts
            .values()
            .filter(|r| r.event.attempt_class == AttemptClass::Unknown)
            .count(),
        details: serde_json::json!({"unit":"predeclared_evidenced_natural_runs","synthetic_readiness_is_separate":true}),
    }
}

fn guardrails(
    rows: &[&RecordedObservation],
    all: &[Journey<'_>],
    request: &ScorecardRequest,
) -> Metric {
    let starts: Vec<_> = all
        .iter()
        .filter(|j| in_window(j.start.event.occurred_at, request))
        .collect();
    let source_bound = starts.iter().filter(|j| primary_touch(j).is_some()).count();
    let linked = starts.iter().filter(|j| j.activation.is_some()).count();
    let mut errors = BTreeMap::<&str, BTreeSet<&str>>::new();
    for row in rows
        .iter()
        .filter(|r| r.event.external() && in_window(r.event.occurred_at, request))
    {
        if let Some(code) = row.event.error_code.as_deref() {
            errors
                .entry(code)
                .or_default()
                .insert(&row.event.attempt_id);
        }
    }
    let mut lags = Vec::new();
    for visible in rows.iter().filter(|r| {
        r.event.event_type == EventType::ReleaseVisible
            && r.event.external()
            && r.event.outcome == Outcome::Pass
    }) {
        if let Some(receipt) = rows
            .iter()
            .filter(|r| {
                r.event.event_type == EventType::PublishAccepted
                    && r.event.external()
                    && checked(&r.event.signed_result_evidence)
                    && r.event.release == visible.event.release
                    && r.event.principal_ref == visible.event.principal_ref
                    && r.event.occurred_at <= visible.event.occurred_at
            })
            .min_by_key(|r| r.event.occurred_at)
        {
            lags.push(visible.event.occurred_at - receipt.event.occurred_at);
        }
    }
    Metric{id:"ACQ-10".into(),value:rows.iter().any(|r|r.event.external()).then(||serde_json::json!({
        "joined_result_coverage":if starts.is_empty(){None}else{Some(linked as f64/starts.len() as f64)},
        "source_coverage":if starts.is_empty(){None}else{Some(source_bound as f64/starts.len() as f64)},
        "finite_failure_reasons":errors.into_iter().map(|(k,v)|(k,v.len())).collect::<BTreeMap<_,_>>(),
        "publication_visibility_lag_ms":lags,"eligible_flow_availability":null,
        "uninstrumented_channel_coverage":null
    })),numerator:Some(linked),denominator:Some(starts.len()),mature_cohort_size:0,pending:0,lost:0,
        unknown:starts.len()-source_bound,details:serde_json::json!({"unit":"instrumented_journeys",
            "missing_service_opportunity_denominator":"unknown","completed_business_does_not_imply_workflow":true})}
}

/// Pure snapshot computation. Arrival-time filtering precedes conflicts and
/// corrections, so later observations never alter an earlier as-of report.
pub(super) fn compute(
    rows: &[RecordedObservation],
    request: &ScorecardRequest,
) -> Result<Scorecard, ObservationError> {
    if request.from >= request.to_exclusive
        || request.as_of < request.from
        || [request.from, request.to_exclusive, request.as_of]
            .into_iter()
            .any(|n| n > MAX_SAFE_INTEGER)
    {
        return Err(ObservationError::Input);
    }
    let visible: Vec<_> = rows
        .iter()
        .filter(|r| r.observed_at <= request.as_of && r.event.occurred_at <= request.as_of)
        .collect();
    let mut versions = BTreeMap::<&str, BTreeSet<&str>>::new();
    for row in &visible {
        versions
            .entry(&row.event.event_id)
            .or_default()
            .insert(&row.payload_sha256);
    }
    let conflicts: BTreeSet<_> = versions
        .iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(k, _)| *k)
        .collect();
    let removed: BTreeSet<_> = visible
        .iter()
        .filter(|r| {
            matches!(
                r.event.event_type,
                EventType::Correction | EventType::Withdrawal
            ) && r.event.evidence.checked()
        })
        .filter_map(|r| r.event.supersedes.as_deref())
        .collect();
    let active: Vec<_> = visible
        .iter()
        .copied()
        .filter(|r| {
            !conflicts.contains(r.event.event_id.as_str())
                && !removed.contains(r.event.event_id.as_str())
                && !matches!(
                    r.event.event_type,
                    EventType::Correction | EventType::Withdrawal
                )
        })
        .collect();
    let grouped = journeys(&active);
    let conflicting_journeys = grouped.iter().filter(|j| j.conflict).count();
    let all: Vec<_> = grouped.into_iter().filter(|j| !j.conflict).collect();
    let mut metrics = Vec::new();
    let mut first = BTreeMap::<&str, &RecordedObservation>::new();
    for j in &all {
        if let Some(a) = j.activation {
            let principal = j.start.event.principal_ref.as_deref().unwrap();
            if first
                .get(principal)
                .is_none_or(|old| a.event.occurred_at < old.event.occurred_at)
            {
                first.insert(principal, a);
            }
        }
    }
    for (id, from, to) in [
        ("ACQ-01", request.from, request.to_exclusive),
        (
            "ACQ-01-24H",
            request.as_of.saturating_sub(DAY),
            request.as_of,
        ),
    ] {
        let count = first
            .values()
            .filter(|a| {
                a.event.occurred_at >= from
                    && a.event.occurred_at < to
                    && a.event.newness == Newness::ProvedNew
                    && a.event.newness_evidence.checked()
            })
            .count();
        let unknown_newness = first
            .values()
            .filter(|a| {
                a.event.occurred_at >= from
                    && a.event.occurred_at < to
                    && (a.event.newness != Newness::ProvedNew
                        || !a.event.newness_evidence.checked())
            })
            .count();
        let mut channels = BTreeMap::<&str, usize>::new();
        for a in first.values().filter(|a| {
            a.event.occurred_at >= from
                && a.event.occurred_at < to
                && a.event.newness == Newness::ProvedNew
                && a.event.newness_evidence.checked()
        }) {
            let channel = all
                .iter()
                .find(|j| j.start.event.journey_id == a.event.journey_id)
                .and_then(primary_touch)
                .and_then(|t| t.event.source_channel)
                .unwrap_or(Channel::Unknown);
            let name = match channel {
                Channel::McpSearch => "mcp_search",
                Channel::AgentEntry => "agent_entry",
                Channel::CanonicalShare => "canonical_share",
                Channel::RepositoryRelease => "repository_release",
                Channel::Direct => "direct",
                Channel::Unknown => "unknown",
            };
            *channels.entry(name).or_default() += 1;
        }
        metrics.push(Metric{id:id.into(),value:(!all.is_empty() && (id!="ACQ-01" || weekly_window(request))).then(||serde_json::json!(count)),numerator:Some(count),denominator:None,
            mature_cohort_size:first.len(),pending:0,lost:0,unknown:unknown_newness,
            details:serde_json::json!({"unit":"verified_first_external_activations","first_observed_not_proved_new":unknown_newness,"primary_source_channels":channels,
                "from":from,"to_exclusive":to,"utc_monday_week":id=="ACQ-01" && weekly_window(request),
                "provisional_interval":id=="ACQ-01" && !weekly_window(request)})});
    }
    metrics.push(activation_cohort("ACQ-02", &all, request, 7 * DAY));
    metrics.push(activation_cohort("ACQ-02-24H", &all, request, DAY));
    metrics.push(funnel("ACQ-03", &all, request, 7 * DAY));
    metrics.push(funnel("ACQ-03-24H", &all, request, DAY));
    metrics.push(cost_metric("ACQ-04", &all, request, 7 * DAY));
    metrics.push(cost_metric("ACQ-04-24H", &all, request, DAY));
    metrics.push(retention("ACQ-05", &all, request, 7 * DAY, 14 * DAY));
    metrics.push(retention(
        "ACQ-05-28-35D",
        &all,
        request,
        28 * DAY,
        35 * DAY,
    ));
    metrics.push(retention("ACQ-05-EARLY48H", &all, request, 0, 2 * DAY));
    metrics.push(publication(&active, request));
    metrics.push(share("ACQ-07", &active, &all, request, 14 * DAY));
    metrics.push(share("ACQ-07-24H", &active, &all, request, DAY));
    metrics.push(supply(&active, &all, request));
    metrics.push(agent_outcomes(&active, request));
    metrics.push(guardrails(&active, &all, request));
    let mut snapshot =
        serde_json::to_vec(&(request, &visible)).map_err(|_| ObservationError::Corrupt)?;
    snapshot.extend_from_slice(b"definition2");
    Ok(Scorecard{definition_version:2,window:request.clone(),window_complete:request.to_exclusive<=request.as_of,
        snapshot_sha256:sha256_hex(&snapshot),visible_observations:visible.len(),
        excluded_synthetic_seed:visible.iter().filter(|r|matches!(r.event.audience_class,Audience::OfficialSeed|Audience::OperatorSynthetic)).count(),
        unknown_audience_binding:visible.iter().filter(|r|!r.event.external() && !matches!(r.event.audience_class,Audience::OfficialSeed|Audience::OperatorSynthetic)).count(),
        conflicting_events:conflicts.len()+conflicting_journeys,metrics,
        coverage_scope:"Explicitly instrumented local observations only; no uninstrumented population denominator".into()})
}
