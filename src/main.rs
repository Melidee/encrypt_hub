use num_primes::Generator;
use std::time::Instant;

fn main() {
    let now = Instant::now();

    {
        encrypt()
    }

    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);
}

fn encrypt() {
    let p = Generator::safe_prime(512);
    println!("{}", p);
    let q = Generator::safe_prime(512);
    println!("{}", q);
    let n = p * q;
    println!("{}", n);
}