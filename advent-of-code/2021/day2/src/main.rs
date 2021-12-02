#![feature(array_windows)]
use std::error::Error;

fn part1(f: &[i32]) -> Result<i32, Box<dyn Error>> {
    let (_, count) = f.iter().copied().fold((i32::MAX, 0), |(prev, count), n| {
        (n, if n > prev { count + 1 } else { count })
    });
    Ok(count)
}

fn part2(f: &[i32]) -> Result<i32, Box<dyn Error>> {
    let (_, count) = f
        .array_windows::<3>()
        .fold((i32::MAX, 0), |(prev, count), win| {
            let sum = win.iter().sum();
            (sum, if sum > prev { count + 1 } else { count })
        });
    Ok(count)
}

fn main() -> Result<(), Box<dyn Error>> {
    scaffold::do_challenge(&[part1, part2])
}
