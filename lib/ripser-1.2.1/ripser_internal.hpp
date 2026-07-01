/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  ripser_internal.hpp a part of Fluent Bit
 *  ==========
 *  Copyright (C) 2025 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef RIPSER_INTERNAL_HPP
#define RIPSER_INTERNAL_HPP

#include <cstdint>
#include <vector>
#include <utility>
#include <cmath>
#include <numeric>
#include <limits>

typedef float    value_t;
typedef int64_t  index_t;
typedef uint16_t coefficient_t;

enum compressed_matrix_layout { LOWER_TRIANGULAR, UPPER_TRIANGULAR };

template <compressed_matrix_layout Layout>
struct compressed_distance_matrix {
    std::vector<value_t> distances;
    std::vector<value_t*> rows;

    compressed_distance_matrix(std::vector<value_t>&& _distances)
        : distances(std::move(_distances)),
          rows((1 + std::sqrt(1 + 8 * distances.size())) / 2) {
        init_rows();
    }

    template <typename DistanceMatrix>
    compressed_distance_matrix(const DistanceMatrix& mat)
        : distances(mat.size() * (mat.size() - 1) / 2), rows(mat.size()) {
        init_rows();
        for (size_t i = 1; i < size(); ++i) {
            for (size_t j = 0; j < i; ++j) {
                rows[i][j] = mat(i, j);
            }
        }
    }

    value_t operator()(const index_t i, const index_t j) const;
    size_t size() const { return rows.size(); }
    void init_rows();
};

typedef compressed_distance_matrix<LOWER_TRIANGULAR> compressed_lower_distance_matrix;
typedef compressed_distance_matrix<UPPER_TRIANGULAR> compressed_upper_distance_matrix;

struct interval_recorder {
    using callback_t = void(*)(int dim, value_t birth, value_t death, void *user_data);

    callback_t cb        = nullptr;
    void      *user_data = nullptr;

    void emit(int dim, value_t birth, value_t death) const {
        if (cb) {
            cb(dim, birth, death, user_data);
        }
    }
};

template <typename DistanceMatrix>
class ripser;

void ripser_run_from_compressed_lower(
    compressed_lower_distance_matrix &&dist,
    index_t dim_max,
    value_t threshold,
    float ratio,
    interval_recorder recorder);

#endif /* RIPSER_INTERNAL_H */
