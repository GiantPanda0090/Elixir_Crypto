# Cryptonetwork

Run iex -S mix to compile Elixir Code

Elixir Cryptography Library.
1. One time pad Modular / XOR
2. Simple RSA Erl :crypto / custom made - 

Demo:

Benchmark:
Cryptonetwork.Rsa.bench_measure(plain_text,[<keysize list>])

Test:
Cryptonetwork.excrypto_encrypt(plain_text,key_size)


3. Diffie-Hellman -

 Demo: Alice exchange message 16 to Bob: 
Cryptonetwork.Diffkeyex.demo(23,16) 

## Installation (not available yet)

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `cryptonetwork` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:cryptonetwork, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/cryptonetwork](https://hexdocs.pm/cryptonetwork).

