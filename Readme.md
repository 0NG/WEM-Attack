```
git clone https://github.com/Z3Prover/z3.git src/3rd/z3

mkdir build

cd build

# should use clang
CC=clang CXX=clang++ cmake ..

make

# 3 round attack
./bin/wem3

# 4 round attack
./bin/wem4

# bench of gaussian elimination
./bin/bench1

# bench of improved gaussian elimination
./bin/bench2

# recover secret sbox from supersbox
./bin/supersbox
```

