use std::time::{Duration, Instant};

/// Reduce `input` to a smaller slice that still satisfies `reproduces`.
///
/// `budget` bounds the total wall-clock time spent minimizing. A single
/// `reproduces` call may overshoot the budget (e.g. an external tool
/// invocation); the deadline is only checked between calls. On expiry the
/// smallest reproducing candidate found so far is returned.
pub fn minimize_failure<F>(input: &[u8], reproduces: F, budget: Duration) -> Vec<u8>
where
    F: Fn(&[u8]) -> bool,
{
    if !reproduces(input) {
        return input.to_vec();
    }

    let deadline = Instant::now() + budget;
    let mut current = input.to_vec();
    let mut chunk = current.len().max(1) / 2;

    'outer: while chunk > 0 && current.len() > 1 {
        let mut changed = false;
        let mut index = 0usize;
        while index < current.len() {
            if Instant::now() >= deadline {
                break 'outer;
            }
            let end = (index + chunk).min(current.len());
            if end == index {
                break;
            }
            let mut candidate = current.clone();
            candidate.drain(index..end);
            if reproduces(&candidate) {
                current = candidate;
                changed = true;
            } else {
                index += chunk;
            }
            if current.len() <= 1 {
                break;
            }
        }

        if !changed {
            chunk /= 2;
        }
    }

    for idx in 0..current.len() {
        if Instant::now() >= deadline {
            break;
        }
        let mut candidate = current.clone();
        candidate[idx] = 0;
        if reproduces(&candidate) {
            current = candidate;
        }
    }

    current
}

#[cfg(test)]
mod tests {
    use super::minimize_failure;
    use std::time::Duration;

    #[test]
    fn minimizes_to_smallest_reproducing_suffix() {
        let data = b"AAAAboomZZZZ";
        let minimized = minimize_failure(
            data,
            |candidate| candidate.windows(4).any(|w| w == b"boom"),
            Duration::from_secs(60),
        );
        assert_eq!(minimized, b"boom");
    }

    #[test]
    fn expired_budget_returns_smallest_reproducing_candidate() {
        let data = vec![7u8; 1024];
        // Budget of zero: the chunk loop exits on the first deadline check,
        // but the initial reproduces() call already confirmed the input
        // reproduces, so the untouched input is returned.
        let minimized = minimize_failure(&data, |_| true, Duration::ZERO);
        assert_eq!(minimized, data);
    }
}
