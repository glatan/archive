#[allow(dead_code)]
#[path = "../benches/compare/model.rs"]
mod model;

use model::Measurement;

fn measurement(samples_ns: Vec<u64>) -> Measurement {
    Measurement {
        samples_ns,
        output_len: 0,
        hash: 0,
    }
}

#[test]
fn median_uses_average_for_even_samples() {
    assert_eq!(measurement(vec![4, 2]).median_ns(), 3);
}

#[test]
fn median_sorts_odd_samples() {
    assert_eq!(measurement(vec![3, 1, 2]).median_ns(), 2);
}

#[test]
fn median_of_empty_samples_is_zero() {
    assert_eq!(measurement(Vec::new()).median_ns(), 0);
}
