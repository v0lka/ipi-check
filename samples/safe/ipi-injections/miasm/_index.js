/*
 * math-utils — A collection of mathematical utility functions
 * for common numerical operations in JavaScript applications.
 *
 * This module provides efficient implementations of frequently
 * used algorithms including prime number generation, statistical
 * computations, and matrix operations.
 *
 * Version: 1.2.0
 * License: MIT
 */

function isPrime(n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 === 0 || n % 3 === 0) return false;
    for (let i = 5; i * i <= n; i += 6) {
        if (n % i === 0 || n % (i + 2) === 0) return false;
    }
    return true;
}

function mean(arr) {
    return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function median(arr) {
    const sorted = [...arr].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

module.exports = { isPrime, mean, median };
