#ifndef _POLYNOMIAL_UTILS_H__
#define _POLYNOMIAL_UTILS_H__

#include <cstdint>
#include <vector>
#include <random>

using namespace std;

class PolynomialWithFastVerification {
public: 
  // Construction: polynomial degree N-1, modulus 
  PolynomialWithFastVerification(uint64_t modulus, int N) : modulus(modulus), N(N) {
    // Precompute the vector (0! % modulus, 1! % modulus, ..., (modulus - 1)! % modulus)
    factorial_table.push_back(1);
    for (int idx = 1; idx < modulus; idx++) {
      factorial_table.push_back(factorial_table[idx-1]*idx % modulus);
    }
    
    // compute ((modulus - 1)!)^{-1} % modulus
    uint64_t base_invert = invMod(factorial_table[modulus-1]);

    // compute ((i!)^{-1} mod modulus)
    // Update the base_invert to (i!)^{-1}
    // (i)^{-1} = base_invert *(i-1)! = (i!)^{-1} * (i-1)!
    // End result: (-, 1^{-1}, 2^{-1}, ..., (modulus-1)^{-1})
    invert_table.resize(modulus);
    for (int idx = modulus-1; idx > 0; idx--) {
      invert_table[idx] = base_invert*factorial_table[idx-1] % modulus;
      base_invert = base_invert*idx % modulus;
    }
  }
  
  // We takes the vector points = (1, 2, ..., i - 1, i + 1, ..., N)
  // Values vals = (p(1), ..., p(N))
  uint64_t compute_p0(vector<uint64_t> points, vector<uint64_t> vals) {
    // looking for the missing point in the points vector.
    int missing_index;
    for (int idx = 0; idx < points.size(); idx++) {
      if ((idx+1) != points[idx]) {
	missing_index = (idx + 1);
	break;
      }
    }
    
    // N_fact = N!
    // scale = N!/u!
    // Assume the missing_index = u
    uint64_t N_fact = factorial_table[N];
    uint64_t scale = N_fact*invert_table[missing_index] % modulus;
    
    // P(x_i) = y_i
    // P(x) = y_1*[(x-x_2)...(x-x_{N-1})]/[(x_1-x_2)...(x_1-x_{N-1})] + ... + y_{N-1}*[(x-x_1)...(x_x_{N-2})]/[(x_{N-1}-x_1)...(x_{N-1}-x_{N-2}]
    // We want to compute P(0), set x = 0
    // The values (x_1 - x_i) will be:
    // Case 1: x_1 != u: [(x_1-x_2)...(x_1-x_{N-1})] = (-1)*(-2)*...*(-(N-2))/(x_1 - missing_index) = (-1)^(N-2)*(N-2)!/(x_1 - missing_index).
    // Case 2: x_1 == u: (-1)*...*(-(N-2)) = (-1)^(N-2)*(N-2)!
    uint64_t sum = 0;
    for (int idx = 0; idx < N-1; idx++) {
      int kdx = points[idx];
      
      // if points[idx] is even, set prod = 1, else, prod = modulus-1.
      // To compute (-1)^(N-2)
      uint64_t prod = (kdx % 2 == 0) ? 1 : (modulus - 1);
      
      // prod = y[idx]*(-1)^{kdx}(points[idx] - missing_index)
      prod = prod*(modulus + kdx - missing_index) % modulus;
      prod = prod*vals[idx] % modulus;
      
	    // (points[idx] - x_1)*...*(points[idx]-x_{idx-1})*(points[idx] - x_{idx+1})*...*(points[idx] - x_{N-1}) 
      // = (j)...(1)(-1)...(-i) = (-1)^i*j!*i!*some_offset_value
      uint64_t k_fact = factorial_table[kdx];
      uint64_t k_fact_inv = invert_table[k_fact];
      
      uint64_t N_minus_k_fact = factorial_table[N - kdx];
      uint64_t N_minus_k_fact_inv = invert_table[N_minus_k_fact];
      
      prod = prod*k_fact_inv % modulus;
      prod = prod*N_minus_k_fact_inv % modulus;   
      
      sum = (sum + prod) % modulus;
    }
    
    return sum*scale % modulus;
  }
  
  uint64_t eval(vector<uint64_t> px, uint64_t x);
    uint64_t invMod(uint64_t a) {
      for (int idx = 1; idx < modulus; idx++) {
      if ((a*idx % modulus) == 1) {
	return idx;
      }
    }
    return 0;
  }

  // To generate P(i) = random_i for i = 1 … (N-1), then compute p(N)

  // ret[i] = P(i+1)
  vector<uint64_t> generate_random_evaluation() {
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, modulus);
    
    vector<uint64_t> ret(N);
    for (int idx = 0; idx < N-1; idx++) {
      ret[idx] = dist(rd);
    }
    
    // Compute ret[N-1] which is p(N) = sum (-1)^(N-k-1)[(N-1)! / (k-1)! (N-k-1)! (N-k)]*P(k)
    uint64_t sum = 0;
    for (int idx = 0; idx < N-1; idx++) {
      // k = idx + 1 --> idx = k - 1;
      int kdx = idx + 1;
      uint64_t sign = (N-kdx-1) % 2 == 0 ? 1 : (modulus - 1);
      
      uint64_t N_minus_1_fact = factorial_table[N - 1];
      
      uint64_t k_minus_1_fact = factorial_table[kdx - 1];
      uint64_t k_minus_1_fact_inv = invert_table[k_minus_1_fact];
      
      uint64_t N_minus_k_fact = factorial_table[N - kdx];
      uint64_t N_minus_k_fact_inv = invert_table[N_minus_k_fact];
	  
      uint64_t prod = sign;
      prod = prod*N_minus_1_fact % modulus;
      prod = prod*k_minus_1_fact_inv % modulus;
      prod = prod*N_minus_k_fact_inv % modulus;
      prod = prod*ret[idx] % modulus;
      
      sum = (sum + prod) % modulus;
    }
    
    ret[N-1] = sum;
    
    return ret;
  }
  
private:
  uint64_t modulus;
  int N;
  vector<uint64_t> factorial_table; // stores 0!, 1!, ..., (N-1)!
  vector<uint64_t> invert_table;   // stores inv(1), ..., inv(N-2)
};

#endif // _POLYNOMIAL_UTILS_H__
