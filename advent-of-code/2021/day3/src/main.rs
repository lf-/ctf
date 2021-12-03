use std::error::Error;

fn part1(f: &[String]) -> Result<String, Box<dyn Error>> {
    let mut bit_freqs = Vec::new();

    for line in f {
        for (i, ch) in line.chars().enumerate() {
            let n = (ch == '1') as u32;
            if i >= bit_freqs.len() {
                bit_freqs.push(n);
            } else {
                bit_freqs[i] += n;
            }
        }
    }
    let majority_round_down = f.len() as u32 / 2;
    let most_common = bit_freqs
        .iter()
        .map(|&n| if n > majority_round_down { '1' } else { '0' })
        .collect::<String>();
    let least_common = bit_freqs
        .iter()
        .map(|&n| if n > majority_round_down { '0' } else { '1' })
        .collect::<String>();
    dbg!(&most_common);
    dbg!(&least_common);
    let gamma = u32::from_str_radix(&most_common, 2).unwrap();
    dbg!(gamma);
    let eps = u32::from_str_radix(&least_common, 2).unwrap();
    dbg!(eps);

    println!("gamma * eps = {}", gamma * eps);

    Ok("".to_string())
}

fn find_common(f: &[&str], digit: char) -> String {
    let mut bit_freqs = Vec::new();
    let other = if digit == '1' { '0' } else { '1' };

    for line in f {
        for (i, ch) in line.chars().enumerate() {
            let n = (ch == '1') as u32;
            if i >= bit_freqs.len() {
                bit_freqs.push(n);
            } else {
                bit_freqs[i] += n;
            }
        }
    }
    // dbg!(&bit_freqs);
    // dbg!(f.len());
    bit_freqs
        .iter()
        .map(|&n| {
            if n >= f.len() as u32 - n {
                digit
            } else {
                other
            }
        })
        .collect::<String>()
}

fn part2(f: &[String]) -> Result<String, Box<dyn Error>> {
    let nlen = f[0].len();

    let doit = |dgt| {
        let mut list: Vec<&str> = f.iter().map(|v| v.as_ref()).collect();

        for i in 0..nlen {
            assert_ne!(list.len(), 0);
            if list.len() == 1 {
                break;
            }
            let mc = find_common(&list, dgt);
            // dbg!(&list);
            // dbg!(&mc);
            let mc = mc.as_bytes();
            list.retain(|num| num.as_bytes()[i] == mc[i]);
        }
        assert_eq!(list.len(), 1);
        list[0]
    };
    let oxy = doit('1');
    let co2 = doit('0');
    println!("oxy: {}", oxy);
    println!("co2: {}", co2);
    println!(
        "lsr: {}",
        u32::from_str_radix(oxy, 2).unwrap() * u32::from_str_radix(co2, 2).unwrap()
    );
    Ok("".to_string())
}

fn main() -> Result<(), Box<dyn Error>> {
    scaffold::do_challenge_s(&[part1, part2])
}
