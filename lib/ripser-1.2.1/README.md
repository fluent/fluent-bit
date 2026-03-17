# Ripser

Copyright © 2015–2021 [Ulrich Bauer].


### Description

Ripser is a lean C++ code for the computation of Vietoris–Rips persistence barcodes. It can do just this one thing, but does it extremely well.

To see a live demo of Ripser's capabilities, go to [live.ripser.org]. The computation happens inside the browser (using [Emscripten] to compile Ripser to [WebAssembly], supported on recent browsers). 

The main features of Ripser:

  - time- and memory-efficient
  - only about 1000 lines of code in a single C++ file
  - support for coefficients in prime finite fields
  - no external dependencies (optional support for Google's [sparsehash])

Currently, Ripser outperforms other codes ([Dionysus], [DIPHA], [GUDHI], [Perseus], [PHAT]) by a factor of more than 40 in computation time and a factor of more than 15 in memory efficiency (for the example linked at [live.ripser.org]). (Note that [PHAT] does not contain code for generating Vietoris–Rips filtrations).

Input formats currently supported by Ripser:

  - comma-separated values lower triangular distance matrix
  - comma-separated values upper triangular distance matrix (MATLAB output from the function `pdist`)
  - comma-separated values full distance matrix
  - [DIPHA] distance matrix data
  - sparse distance matrix in sparse triplet format
  - binary lower triangular distance matrix
  - point cloud data

Ripser's efficiency is based on a few important concepts and principles, building on key previous and concurrent developments by other researchers in computational topology:
  
  - Compute persistent *co*homology (as suggested by [Vin de Silva, Dmitriy Morozov, and Mikael Vejdemo-Johansson](https://doi.org/10.1088/0266-5611/27/12/124003))
  - Use the chain complex property that boundaries are cycles
    (employ the *clearing* optimization, aka *persistence with a twist*, as suggested by [Chao Chen and Michael Kerber](http://www.geometrie.tugraz.at/kerber/kerber_papers/ck-phcwat-11.pdf))
  - If no threshold is specified, choose the *enclosing radius* as the threshold, from which on homology is guaranteed to be trivial (as suggested by [Greg Henselman-Petrusek](https://github.com/Eetion/Eirene.jl))
  - Don't store information that can be readily recomputed (in particular, the original and the reduced boundary matrix)
  - Take computational shortcuts (*apparent* and *emergent persistence pairs*)


### Version
[Latest release][latest-release]: 1.2.1 (March 2021)


### Building

Ripser requires a C++11 compiler. Here is how to obtain, build, and run Ripser:

```sh
git clone https://github.com/Ripser/ripser.git
cd ripser
make
./ripser examples/sphere_3_192.lower_distance_matrix
```


### Options

Ripser supports several compile-time options. They are switched on by defining the C preprocessor macros listed below, either using `#define` in the code or by passing an argument to the compiler. The following options are supported:

  - `USE_COEFFICIENTS`: enable support for coefficients in a prime field
  - `INDICATE_PROGRESS`: indicate the current progress in the console
  - `PRINT_PERSISTENCE_PAIRS`: output the computed persistence pairs (enabled by default in the code; comment out to disable)
  - `USE_ROBINHOOD_HASHMAP`: enable support for Martin Ankerl's [robinhoodhash] data structure; may further reduce memory footprint

For example, to build Ripser with support for Martin Ankerl's robin hood hashmap:

```sh
$ c++ -std=c++11 ripser.cpp -o ripser -O3 -D NDEBUG -D USE_ROBINHOOD_HASHMAP
```

A Makefile is provided with some variants of the above options. Use `make all` to build them. The default `make` builds a binary with the default options.

The input is given either in a file whose name is passed as an argument, or through stdin. The following options are supported at the command line:

  - `--format`: use the specified file format for the input.  The following formats are supported:
    - `lower-distance`: lower triangular distance matrix; a comma (or whitespace, or other non-numerical character) separated list of the distance matrix entries below the diagonal, sorted lexicographically by row index, then column index.
    - `upper-distance`: upper triangular distance matrix; similar to the previous, but for the entries above the diagonal; suitable for output from the MATLAB functions `pdist` or  `seqpdist`, exported to a CSV file.
    - `distance`  (default if no format is specified): full distance matrix; similar to the above, but for all entries of the distance matrix. One line per row of the matrix; only the part below the diagonal is actually read.
    - `dipha`: DIPHA distance matrix as described on the [DIPHA] website.
    - `point-cloud`: point cloud; a comma (or whitespace, or other non-numerical character) separated list of coordinates of the points in some Euclidean space, one point per line.
    - `binary`: lower distance matrix in binary file format; a sequence of the distance matrix entries below the diagonal in 32 bit float format (IEEE 754, single, little endian).
    - `sparse`: sparse triplet format; a whitespace separated list of entries of a sparse distance matrix, one entry per line, each of the form *i j d(i,j)* specifying the distance between points *i* and *j*.  Each pair of points should appear in the file at most once.
  - `--dim k`: compute persistent homology up to dimension *k*.
  - `--threshold t`: compute Rips complexes up to diameter *t*.
  - `--modulus p`: compute homology with coefficients in the prime field Z/*p*Z (only available when built with the option `USE_COEFFICIENTS`).
  - `--ratio r`: only show persistence pairs with death/birth ratio > *r*.



### Experimental features

The following experimental features are currently available in separate branches:

- `representative-cocycles`: output of representative cocycles for persistent cohomology.
- `representative-cycles`: computation and output of representative cycles for persistent homology (in the standard version, only *co*cycles are computed).
- `simple`: a simplified version of Ripser, without support for sparse distance matrices and coefficients.  This might be a good starting point for exploring the code.


### Citing

If you use Ripser in your research or if you want to give a reference to Ripser in a paper, you may use the following bibtex entry (will be updated with complete publication data):

```
@misc{1908.02518,
	Author = {Ulrich Bauer},
	Title = {Ripser: efficient computation of Vietoris-Rips persistence barcodes},
	Month = Feb,
	Year = {2021},
	Eprint = {1908.02518v2},
	Note = {Preprint}
}
```


### License

Ripser is licensed under the [MIT] license (`COPYING.txt`), with an extra clause (`CONTRIBUTING.txt`) clarifying the license for modifications released without an explicit written license agreement.  Please contact the author if you want to use Ripser in your software under a different license. 

[Ulrich Bauer]: <http://ulrich-bauer.org>
[live.ripser.org]: <http://live.ripser.org>
[Emscripten]: <http://emscripten.org>
[WebAssembly]: <https://webassembly.org>
[latest-release]: <https://github.com/Ripser/ripser/releases/latest>
[Dionysus]: <http://www.mrzv.org/software/dionysus/>
[DIPHA]: <http://git.io/dipha>
[PHAT]: <http://git.io/dipha>
[Perseus]: <http://www.sas.upenn.edu/~vnanda/perseus/>
[GUDHI]: <http://gudhi.gforge.inria.fr>
[robinhoodhash]: <https://github.com/martinus/robin-hood-hashing>
[MIT]: <https://opensource.org/licenses/mit-license.php>
