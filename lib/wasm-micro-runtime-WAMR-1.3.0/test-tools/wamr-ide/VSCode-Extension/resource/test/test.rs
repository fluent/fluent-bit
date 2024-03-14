/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

use std::collections::HashMap;
use std::collections::VecDeque;
use std::cell::RefCell;

fn main() {
    let mut vector = Vec::from([1, 2, 3, 4]);
    vector.push(12);

    let mut map: HashMap<&str, f64> = HashMap::from([
        ("Mercury", 0.4),
        ("Venus", 0.7),
        ("Earth", 1.0),
        ("Mars", 1.5),
    ]); 
    map.insert("Venus", 2.5);
    map.insert("Sun", 312.2);

    let string = "this is a string";

    let tmp = String::from("hello world");
    let slice = &tmp[1..5];

    let mut deque = VecDeque::from([1, 2, 3]);
    deque.push_back(4);
    deque.push_back(5);   

    let ref_cell = RefCell::new(5);

    println!("Hello, world!"); // BP_MARKER_1
}