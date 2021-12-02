use std::{env::args, error::Error, fs};

type Chall = fn(&[i32]) -> Result<i32, Box<dyn Error>>;

pub fn do_challenge(parts: &[Chall]) -> Result<(), Box<dyn Error>> {
    let mut my_args = args().skip(1);
    let chall_number = my_args.next().ok_or("Missing challenge number")?;
    let fname = my_args.next().unwrap_or("input.txt".to_string());

    let input = fs::read_to_string(fname)?;
    let input = input
        .split('\n')
        .filter(|s| !s.is_empty())
        .map(|n| n.parse::<i32>())
        .collect::<Result<Vec<_>, _>>()?;

    let chall_number: u32 = chall_number.parse()?;
    let n = parts[chall_number as usize - 1](&input)?;

    println!("{n}");
    Ok(())
}
