pub fn minimize_failure<F>(input: &[u8], reproduces: F) -> Vec<u8>
where
    F: Fn(&[u8]) -> bool,
{
    if !reproduces(input) {
        return input.to_vec();
    }

    let mut current = input.to_vec();
    let mut chunk = current.len().max(1) / 2;

    while chunk > 0 && current.len() > 1 {
        let mut changed = false;
        let mut index = 0usize;
        while index < current.len() {
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

    #[test]
    fn minimizes_to_smallest_reproducing_suffix() {
        let data = b"AAAAboomZZZZ";
        let minimized =
            minimize_failure(data, |candidate| candidate.windows(4).any(|w| w == b"boom"));
        assert_eq!(minimized, b"boom");
    }
}
