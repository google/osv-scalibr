use smallvec::SmallVec;

fn main() {
    let mut v: SmallVec<[i32; 4]> = SmallVec::new();
    v.push(1);

    // This is a vulnerable function (RUSTSEC-2021-0003)
    // v.insert_many(1, [2, 3]);

    println!("{:?}", v);
}
