#![feature(array_windows)]
use std::{env::args, error::Error, fs};

fn part1(f: &[u32]) -> Result<u32, Box<dyn Error>> {
    let (_, count) = f.iter().copied().fold((u32::MAX, 0), |(prev, count), n| {
        (n, if n > prev { count + 1 } else { count })
    });
    Ok(count)
}

fn part2(f: &[u32]) -> Result<u32, Box<dyn Error>> {
    let (_, count) = f
        .array_windows::<3>()
        .fold((u32::MAX, 0), |(prev, count), win| {
            let sum = win.iter().sum();
            (sum, if sum > prev { count + 1 } else { count })
        });
    Ok(count)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut my_args = args().skip(1);
    let chall_number = my_args.next().ok_or("Missing challenge number")?;
    let fname = my_args.next().unwrap_or("input.txt".to_string());

    let f = fs::read_to_string(fname)?;
    let f = f
        .split('\n')
        .filter(|s| !s.is_empty())
        .map(|n| n.parse::<u32>())
        .collect::<Result<Vec<_>, _>>()?;

    let n = match chall_number.as_str() {
        "1" => part1(&f),
        "2" => part2(&f),
        _ => Err("Unknown challenge number".into()),
    }?;
    println!("{n}");

    Ok(())
}
