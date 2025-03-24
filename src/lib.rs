#![allow(non_snake_case)]
pub mod frodo {
    use byteorder::{ByteOrder, LittleEndian};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake128,
    };
    use std::error::Error;
    use std::fmt;

    // Constants for Frodo
    const N: usize = 640; // Matrix dimension
    const N_BAR: usize = 8; // Number of message bits
    const M_BAR: usize = 8; // Number of message bits
    const L: i16 = 2; // Range parameter
    const SIGMA: f64 = 1.0; // Standard deviation
    const SEED_LENGTH: usize = 32;
    const SHARED_SECRET_BYTES: usize = 32; // Shared secret length

    #[derive(Debug)]
    pub enum FrodoError {
        DeserializationError(String),
    }

    impl fmt::Display for FrodoError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                FrodoError::DeserializationError(msg) => {
                    write!(f, "Deserialization error: {}", msg)
                }
            }
        }
    }

    impl Error for FrodoError {}

    #[derive(Clone)]
    pub struct Matrix {
        rows: usize,
        cols: usize,
        data: Vec<i16>,
    }

    impl Matrix {
        pub fn new(rows: usize, cols: usize) -> Self {
            Matrix {
                rows,
                cols,
                data: vec![0; rows * cols],
            }
        }

        pub fn get(&self, row: usize, col: usize) -> i16 {
            self.data[row * self.cols + col]
        }

        pub fn set(&mut self, row: usize, col: usize, value: i16) {
            self.data[row * self.cols + col] = value;
        }

        pub fn multiply(&self, other: &Matrix) -> Matrix {
            assert_eq!(self.cols, other.rows);

            // q = 2^15
            const Q: i32 = 32768;

            let mut result = Matrix::new(self.rows, other.cols);

            for i in 0..self.rows {
                for j in 0..other.cols {
                    let mut sum: i32 = 0; // Use i32 to prevent overflow during accumulation
                    for k in 0..self.cols {
                        sum = (sum + (self.get(i, k) as i32 * other.get(k, j) as i32)) % Q;
                    }
                    result.set(i, j, sum as i16); // Convert back to i16 after modulo
                }
            }

            result
        }

        pub fn transpose(&self) -> Matrix {
            let mut result = Matrix::new(self.cols, self.rows);

            for i in 0..self.rows {
                for j in 0..self.cols {
                    result.set(j, i, self.get(i, j));
                }
            }

            result
        }

        pub fn serialize(&self) -> Vec<u8> {
            let mut result = Vec::with_capacity(self.rows * self.cols * 2);
            for &value in &self.data {
                let mut bytes = [0u8; 2];
                LittleEndian::write_i16(&mut bytes, value);
                result.extend_from_slice(&bytes);
            }
            result
        }

        pub fn deserialize(data: &[u8], rows: usize, cols: usize) -> Result<Self, FrodoError> {
            if data.len() < rows * cols * 2 {
                return Err(FrodoError::DeserializationError(
                    "Not enough data".to_string(),
                ));
            }

            let mut matrix = Matrix::new(rows, cols);
            for i in 0..rows {
                for j in 0..cols {
                    let idx = (i * cols + j) * 2;
                    matrix.set(i, j, LittleEndian::read_i16(&data[idx..idx + 2]));
                }
            }

            Ok(matrix)
        }
    }

    #[derive(Clone)]
    pub struct PublicKey {
        seed_a: [u8; SEED_LENGTH],
        matrix_b: Matrix,
    }

    impl PublicKey {
        pub fn serialize(&self) -> Vec<u8> {
            let mut result = Vec::with_capacity(SEED_LENGTH + N * N_BAR * 2);
            result.extend_from_slice(&self.seed_a);
            result.extend_from_slice(&self.matrix_b.serialize());
            result
        }

        pub fn deserialize(data: &[u8]) -> Result<Self, FrodoError> {
            if data.len() < SEED_LENGTH + N * N_BAR * 2 {
                return Err(FrodoError::DeserializationError(
                    "Invalid public key size".to_string(),
                ));
            }

            let mut seed_a = [0u8; SEED_LENGTH];
            seed_a.copy_from_slice(&data[0..SEED_LENGTH]);

            let matrix_b = Matrix::deserialize(&data[SEED_LENGTH..], N, N_BAR)?;

            Ok(PublicKey { seed_a, matrix_b })
        }
    }

    #[derive(Clone)]
    pub struct SecretKey {
        matrix_s_transpose: Matrix,
    }

    impl SecretKey {
        pub fn serialize(&self) -> Vec<u8> {
            self.matrix_s_transpose.serialize()
        }

        pub fn deserialize(data: &[u8]) -> Result<Self, FrodoError> {
            let matrix_s_transpose = Matrix::deserialize(data, N_BAR, N)?;
            Ok(SecretKey { matrix_s_transpose })
        }
    }

    #[derive(Clone)]
    pub struct Ciphertext {
        matrix_b_prime: Matrix,
        matrix_v_prime: Matrix,
    }

    impl Ciphertext {
        pub fn serialize(&self) -> Vec<u8> {
            let mut result = Vec::new();
            result.extend_from_slice(&self.matrix_b_prime.serialize());
            result.extend_from_slice(&self.matrix_v_prime.serialize());
            result
        }

        pub fn deserialize(data: &[u8]) -> Result<Self, FrodoError> {
            if data.len() < (N * M_BAR + N_BAR * M_BAR) * 2 {
                return Err(FrodoError::DeserializationError(
                    "Invalid ciphertext size".to_string(),
                ));
            }

            let b_prime_size = N * M_BAR * 2;
            let matrix_b_prime = Matrix::deserialize(&data[0..b_prime_size], N, M_BAR)?;
            let matrix_v_prime = Matrix::deserialize(&data[b_prime_size..], N_BAR, M_BAR)?;

            Ok(Ciphertext {
                matrix_b_prime,
                matrix_v_prime,
            })
        }
    }

    pub struct Frodo {
        message_bytes: usize,
    }

    impl Default for Frodo {
        fn default() -> Self {
            Frodo {
                message_bytes: SHARED_SECRET_BYTES,
            }
        }
    }

    impl Frodo {
        // Generate matrix A from seed
        fn generate_a(&self, seed: &[u8]) -> Matrix {
            let mut matrix_a = Matrix::new(N, N);
            let mut shake = Shake128::default();
            shake.update(seed);
            let mut reader = shake.finalize_xof();

            let mut buffer = [0u8; 2];
            for i in 0..N {
                for j in 0..N {
                    reader.read(&mut buffer);
                    matrix_a.set(i, j, LittleEndian::read_i16(&buffer));
                }
            }

            matrix_a
        }

        // Sample from discrete Gaussian distribution
        fn sample_gaussian(&self, seed: &[u8], nonce: u64) -> i16 {
            // Use the pseudocode algorithm for Gaussian sampling
            let mut rng = StdRng::from_seed(derive_seed(seed, nonce));

            // Calculate probability p = 1/2 + sqrt(1/2 - SIGMA/(2*L+1))
            let p = 0.5 + (0.5 - SIGMA / (2.0 * (L as f64) + 1.0)).sqrt();

            // Count random samples less than p
            let mut count = 0;
            for _ in -L..=L {
                if rng.gen::<f64>() < p {
                    count += 1;
                }
            }

            // Return the count offset by L
            count - L
        }

        // Generate random noise matrix
        fn generate_noise(
            &self,
            rows: usize,
            cols: usize,
            seed: &[u8],
            start_nonce: u64,
        ) -> Matrix {
            let mut matrix = Matrix::new(rows, cols);
            let mut nonce = start_nonce;

            for i in 0..rows {
                for j in 0..cols {
                    matrix.set(i, j, self.sample_gaussian(seed, nonce));
                    nonce += 1;
                }
            }

            matrix
        }

        // Encode a message into a matrix
        fn encode(&self, message: &[u8]) -> Matrix {
            let mut matrix = Matrix::new(N_BAR, M_BAR);

            // Simple encoding: each byte from the message becomes an element in the matrix
            // In a real implementation, this would be more sophisticated
            let mut idx = 0;
            for i in 0..N_BAR {
                for j in 0..M_BAR {
                    if idx < message.len() {
                        matrix.set(i, j, message[idx] as i16);
                        idx += 1;
                    }
                }
            }

            matrix
        }

        // Decode a matrix to retrieve the message
        fn decode(&self, matrix: &Matrix) -> Vec<u8> {
            let mut message = Vec::with_capacity(self.message_bytes);

            // Simple decoding: each element in the matrix becomes a byte in the message
            // In a real implementation, this would handle errors and be more sophisticated
            let mut idx = 0;
            for i in 0..N_BAR {
                for j in 0..M_BAR {
                    if idx < self.message_bytes {
                        message.push(matrix.get(i, j) as u8);
                        idx += 1;
                    }
                }
            }

            message
        }

        // Key generation
        pub fn keygen(&self) -> (PublicKey, SecretKey) {
            // Generate random seeds
            let seed_a = random_bytes(SEED_LENGTH);
            let seed_se = random_bytes(SEED_LENGTH);

            // Generate matrix A from seed
            let matrix_a = self.generate_a(&seed_a);

            // Generate S and E with error distribution
            let matrix_s = self.generate_noise(N, N_BAR, &seed_se, 0);
            let matrix_e = self.generate_noise(N, N_BAR, &seed_se, (N * N_BAR) as u64);

            // Calculate B = A*S + E
            let mut matrix_b = matrix_a.multiply(&matrix_s);

            // Add E to B
            for i in 0..N {
                for j in 0..N_BAR {
                    let val = matrix_b.get(i, j) + matrix_e.get(i, j);
                    matrix_b.set(i, j, val);
                }
            }

            // Public key is (seed_a, B), secret key is S^T
            let mut seed_a_array = [0u8; SEED_LENGTH];
            seed_a_array.copy_from_slice(&seed_a);

            (
                PublicKey {
                    seed_a: seed_a_array,
                    matrix_b,
                },
                SecretKey {
                    matrix_s_transpose: matrix_s.transpose(),
                },
            )
        }

        // Encapsulation
        pub fn encaps(&self, pk: &PublicKey) -> (Ciphertext, Vec<u8>) {
            // Generate random message
            let message = random_bytes(self.message_bytes);

            // Generate matrix A from seed
            let matrix_a = self.generate_a(&pk.seed_a);

            // Generate random seed for S' and E'
            let seed_se = random_bytes(SEED_LENGTH);

            // Generate S', E', and E'' with error distribution
            let matrix_s_prime = self.generate_noise(N, M_BAR, &seed_se, 0);
            let matrix_e_prime = self.generate_noise(N, M_BAR, &seed_se, (N * M_BAR) as u64);
            let matrix_e_double_prime =
                self.generate_noise(N_BAR, M_BAR, &seed_se, (N * M_BAR + N * M_BAR) as u64);

            // Calculate B' = S'*A + E'
            let matrix_s_prime_transpose = matrix_s_prime.transpose();
            let mut matrix_b_prime = matrix_a.multiply(&matrix_s_prime);

            // Add E' to B'
            for i in 0..N {
                for j in 0..M_BAR {
                    let val = matrix_b_prime.get(i, j) + matrix_e_prime.get(j, i);
                    matrix_b_prime.set(i, j, val);
                }
            }

            // Calculate V = S'*B + E''
            let mut matrix_v = matrix_s_prime_transpose.multiply(&pk.matrix_b);

            // Add E'' to V
            for i in 0..N_BAR {
                for j in 0..M_BAR {
                    let val = matrix_v.get(i, j) + matrix_e_double_prime.get(j, i);
                    matrix_v.set(i, j, val);
                }
            }

            // Encode the message
            let encoded_msg = self.encode(&message);

            // Add encoded message to V
            let mut matrix_v_prime = Matrix::new(N_BAR, M_BAR);
            for i in 0..N_BAR {
                for j in 0..M_BAR {
                    matrix_v_prime.set(i, j, matrix_v.get(i, j) + encoded_msg.get(i, j));
                }
            }

            // Create ciphertext (B', V')
            let ciphertext = Ciphertext {
                matrix_b_prime,
                matrix_v_prime,
            };

            (ciphertext, message)
        }

        // Decapsulation
        pub fn decaps(&self, sk: &SecretKey, ct: &Ciphertext) -> Vec<u8> {
            // Calculate C2 - C1*SK^T
            let product = ct.matrix_b_prime.multiply(&sk.matrix_s_transpose);

            let mut result = Matrix::new(N_BAR, M_BAR);
            for i in 0..N_BAR {
                for j in 0..M_BAR {
                    result.set(i, j, ct.matrix_v_prime.get(i, j) - product.get(i, j));
                }
            }

            // Decode the result to get the shared secret
            self.decode(&result)
        }
    }

    // Helper function to generate random bytes
    fn random_bytes(length: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; length];
        rng.fill(&mut bytes[..]);
        bytes
    }

    // Helper function to derive a seed from a base seed and a nonce
    fn derive_seed(base_seed: &[u8], nonce: u64) -> [u8; 32] {
        let mut shake = Shake128::default();
        shake.update(base_seed);

        // Add nonce to the hash
        let mut nonce_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut nonce_bytes, nonce);
        shake.update(&nonce_bytes);

        let mut seed = [0u8; 32];
        shake.finalize_xof().read(&mut seed);
        seed
    }
}
