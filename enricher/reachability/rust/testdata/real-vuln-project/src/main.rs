use smallvec::SmallVec;

fn main() {
    let mut v: SmallVec<[i32; 4]> = SmallVec::new();
    v.push(1);

    // This is an unreachable vulnerable function
    // v.insert_many(1, [2, 3]);

    println!("{:?}", v);
}
