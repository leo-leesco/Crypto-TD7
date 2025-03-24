# FrodoKEM implementation

Please check the latest version on [GitHub](https://github.com/leo-leesco/Crypto-TD7).

## Build

`cargo build` produces `frodokeygen`, `frodoencaps` and `frododecaps` in `target/debug`.

If you want the optimized version, run `cargo build --release`, and the executables can then be found in `target/release`.

## Requirements

`frodokeygen` expects and writes to :

- `<publickey_file_path>`
- `<secretkey_file_path>`

`frodoencaps` expects :

- `<publickey_file_path>`
- `<ciphertext_file_path>` (written to)
- `<sharedsecretkey_file_path>` (written to)

`frododecaps` expects :

- `<privatekey_file_path>`
- `<ciphertext_file_path>`
- `<sharedsecretkey_file_path>` (written to)

## Theoretical framework

### `keygen`

```pseudo
sA = random_int()
sSE = random_int()
A = Frodo.from_seed(sA)
S = shake.random(N*n, seed = sSE, normal distribution)
E = shake.random(N*n, seed = sSE, normal distribution)
B = AS + E
return (PK = (sA,B), SK = S^T)
```

We define generating $A$ from $s_A$ as :
```pseudo

A = shake.random(N*N, seed = sA)
```

We need to draw following a normal distribution, between $[-\ell,\ell]$ with standard deviation $\sigma$. To do this, we simply draw $2\ell+1$ coin tosses with probability $p$ and then offset so as to fit in the desired support. The standard deviation is $(2\ell+1)p(1-p)=\sigma$, i.e. $p=\frac12\pm\sqrt{\frac12-\frac s{2\ell+1}}$. This leads to the Gaussian noise generator :
```pseudo
p=1/2+sqrt(1/2-s/(2L+1))
return count(shake.random(seed = sSE,uniform in [0,1])<p for _ in -L..=L) - L
```

### `frodoencaps`

```pseudo
A = Frodo.from_seed(s_A)
sSE = random_int()
S = shake.random(N*m, seed = sSE, normal distribution)
E = shake.random(N*m, seed = sSE, normal distribution)
Ep = shake.random(n*m, seed = sSE, normal distribution)
Bp = SA + E
V  = SB + Ep
return (Bp, V + Frodo.encode(message))
```

### `frododecaps`

```pseudo
return Frodo.decode(C2-C1*SK^T)
```
