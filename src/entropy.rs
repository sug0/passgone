use std::ops::ControlFlow;

pub fn shannon(string: &str) -> f64 {
    let slen = string.len() as f64;
    let result = string
        .as_bytes()
        .iter()
        .copied()
        .fold(Box::new([0usize; 256]), |mut accum, ch| {
            accum[ch as usize] += 1;
            accum
        })
        .iter()
        .filter(|&&count| count > 0)
        .try_fold(0f64, |accum, &count| {
            let freq = count as f64 / slen;
            let log256_freq = freq.log(256.0);
            if log256_freq.is_infinite() {
                ControlFlow::Break(f64::INFINITY)
            } else {
                ControlFlow::Continue(accum - freq * log256_freq)
            }
        });
    match result {
        ControlFlow::Break(inf) => inf,
        ControlFlow::Continue(entropy) => entropy,
    }
}
