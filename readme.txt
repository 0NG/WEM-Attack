```
mkdir build

cd build

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
```

