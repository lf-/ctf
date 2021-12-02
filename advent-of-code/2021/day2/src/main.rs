use std::error::Error;

fn part1(f: &[String]) -> Result<String, Box<dyn Error>> {
    let mut h = 0i32;
    let mut v = 0i32;

    for cmd in f {
        let mut i = cmd.split(' ');
        let p1 = i.next().unwrap();
        let p2: i32 = i.next().unwrap().parse().unwrap();

        match p1 {
            "forward" => h += p2,
            "down" => v += p2,
            "up" => v -= p2,
            _ => todo!(),
        }
    }
    println!("{}", h * v);
    Ok("".to_string())
}

fn part2(f: &[String]) -> Result<String, Box<dyn Error>> {
    let mut h = 0i32;
    let mut aim = 0i32;
    let mut v = 0i32;

    for cmd in f {
        let mut i = cmd.split(' ');
        let p1 = i.next().unwrap();
        let p2: i32 = i.next().unwrap().parse().unwrap();

        match p1 {
            "forward" => {
                h += p2;
                v += aim * p2;
            }
            "down" => aim += p2,
            "up" => aim -= p2,
            _ => todo!(),
        }
    }
    println!("{}", h * v);
    Ok("".to_string())
}

fn main() -> Result<(), Box<dyn Error>> {
    scaffold::do_challenge_s(&[part1, part2])
}
