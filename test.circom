template Example () {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b + 3;
}

component main { public [ b ] } = Example();

/* INPUT = {
    "a": "5",
    "b": "11"
} */
