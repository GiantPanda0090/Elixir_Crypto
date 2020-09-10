defmodule Cryptonetwork.Rsa do

  import Math
  import Benchwarmer

  def native_main(plain_text,n,e,d) do
    cipher_rsa = :crypto.public_encrypt(:rsa, plain_text, [e,n], :rsa_pkcs1_padding)
    out_native = :base64.encode_to_string(cipher_rsa)
    plain = :crypto.private_decrypt(:rsa, cipher_rsa, [e,n,d], :rsa_pkcs1_padding)
     %{plain_text: plain_text,plain_text_afterdecrypt: plain,cipher: out_native}
  end

  def mix_main(text,n,e,d,p) do
    plain_text = to_charlist text
    bit_size = byte_size  text
      public = {n,e}
    private = {n,d}
    new_plain_text = padding_pkcs(plain_text,bit_size,p)
    cipher = rsa_encrypt(new_plain_text, public)

    plain = :crypto.private_decrypt(:rsa, cipher, [e,n,d], :rsa_pkcs1_padding)
     %{plain_text: plain_text,plain_text_afterdecrypt: plain,cipher: cipher}

  end



  def custom_main_ex(text,n,e,d,p) do
    plain_text = to_charlist text
  bit_size = byte_size  text
    public = {n,e}
  private = {n,d}
  new_plain_text = padding_pkcs(plain_text,bit_size,p)
  cipher = rsa_encrypt(new_plain_text, public)
  out = :base64.encode_to_string(cipher)
  plain = remove_padding_pkcs(rsa_decrypt(cipher,private))
  %{plain_text: plain_text,plain_text_afterdecrypt: plain,cipher: out}
  end


  def custom_main(p,q,text) do
  plain_text = to_charlist text
  {public,private} = get_key(p,q) ##public/private key
  bit_size = byte_size  text
  new_plain_text = padding_pkcs(plain_text,bit_size,p)
  cipher = rsa_encrypt(new_plain_text, public)
  out = :base64.encode_to_string(cipher)
  plain = remove_padding_pkcs(rsa_decrypt(cipher,private))
  %{plain_text: plain_text,plain_text_afterdecrypt: plain,cipher: out}
  end

  def custom_main(p,q,e, text) do
    plain_text = to_charlist text
  {public,private} = get_key(p,q,e) ##public/private key
  bit_size = byte_size  text
  new_plain_text = padding_pkcs(plain_text,bit_size,p)
  cipher = rsa_encrypt(new_plain_text, public)
  out = :base64.encode_to_string(cipher)

  plain = remove_padding_pkcs(rsa_decrypt(cipher,private))
  %{plain_text: plain_text,plain_text_afterdecrypt: plain,cipher: out}
  end
##https://stackoverflow.com/questions/52017631/delete-all-entries-of-an-element-of-a-list-in-elixir-not-just-the-first-one
  def remove_padding_pkcs(bit_str) do
    lst = to_charlist bit_str
    pad = List.last(lst)
    plaintext_length = length(lst) - pad
    lst
    |> Enum.slice(0, plaintext_length)
  end

  def padding_pkcs(plain_text,bit_size,p) do
    bit = byte_size(:binary.encode_unsigned(p)) - bit_size
    if bit < 0 do
      raise  ArgumentError, message: "Include plain text is  bigger than prime, p = " <> to_string p
    else
      list_append(plain_text, bit,1,[])
  end
end

  def list_append(plain_text, bit,init,lst) do
    padding = [bit | lst]
     if init < bit do
      list_append(plain_text,bit,init+1, padding)
     else
      out = Enum.concat(plain_text , padding)
      out
     end

  end


  def get_e(w,init) do
    if Integer.gcd(w,init) != 1 and init < w do
      get_e(w,init+1)
    else
      init
    end
  end

  def get_key(p,q,e) do ## manual specify e
    n=p*q
    w=(p-1)*(q-1)
    {:ok, d} = Math.mod_inv(e, w)
    {{n,e},{n,d}}
  end

  def get_key(p,q) do
    n=p*q
    w=(p-1)*(q-1)
    e = get_e(w,2)
    {:ok, d} = Math.mod_inv(e, w)
    {{n,e},{n,d}}
  end

  ## Referenece http://erlang.org/pipermail/erlang-questions/2009-June/044861.html
  def rsa_encrypt(plain_text,{n,e}) do
   rsa_private_encrypt(plain_text,[:binary.encode_unsigned(n),e],[])
  end

  def rsa_decrypt(cipher,{n,d}) do
  plain_text = rsa_public_decrypt(cipher,[:binary.encode_unsigned(n),d])
  #plain_text_decode = binary_to_list(plain_text)
  end


  def rsa_private_encrypt(h,[n ,e],cipher) do
    size = byte_size(List.to_string(h))
    <<h::size*8>> = List.to_string(h)
    size = byte_size(n)
    <<n_int::size*8>> = n
    if h >= n_int do
      raise  ArgumentError, message: "Include lettters bigger than N, N = " <> to_string n
    else
    ciph = :crypto.mod_pow(h,e,n_int)
  end
  end

  require Integer

  def  pow_cus(n, k), do: pow_cus(n, k, 1)
  defp pow_cus(_, 0, acc), do: acc
  defp pow_cus(n, k, acc), do: pow_cus(n, k - 1, n * acc)

  def rsa_public_decrypt(h,[n ,d]) do
    size = byte_size(n)
    <<n_int::size*8>> = n
    size = byte_size(h)
    <<h::size*8>> = h
    if h >= n_int do
      raise  ArgumentError, message: "Include lettters bigger than N, N = " <> to_string n
    else
     #N^P mod M
    plain = :crypto.mod_pow(h,d,n_int)
    end
  end

  ##Reference https://hexdocs.pm/ex_crypto/readme.html
  def excrypto_encrypt(plain_text,key_1) do
    {pem, 0} = System.cmd "openssl", ["genrsa",key_1]
    key = pem    |> :public_key.pem_decode |> List.first |> :public_key.pem_entry_decode
    {:RSAPrivateKey, :'two-prime', n , e, d, p, q, _e1, _e2, _c, _other} =key
    rsa_native = native_main(plain_text,n,e,d)

    rsa_custom =  custom_main(p,q,e,plain_text)
    rsa_custom_new = custom_main_ex(plain_text,n,e,d,p)
    mix_custom = 0# mix_main(plain_text,n,e,d,p)
    %{native: rsa_native, custom: rsa_custom,custom_new: rsa_custom_new, mix_custom: mix_custom}
       #IO.puts "Custom complete. Output string: " <> to_string out_custom
    end

    def bench_measure(plain_text,[key_1| tail]) do
      IO.puts "Measuring Benchmark for " <> to_string key_1 <> "bits"
      {pem, 0} = System.cmd "openssl", ["genrsa",key_1], stderr_to_stdout: true
      key = pem    |> :public_key.pem_decode |> List.first |> :public_key.pem_entry_decode
      {:RSAPrivateKey, :'two-prime', n , e, d, p, q, _e1, _e2, _c, _other} =key

      IO.puts "Benchmark for Native :crypto function "
      Benchwarmer.benchmark (fn ->
        rsa_native = native_main(plain_text,n,e,d)
      end)

      IO.puts "Benchmark for Custom  function "
      Benchwarmer.benchmark (fn ->
        rsa_custom =  custom_main(p,q,e,plain_text)
      end)
      IO.puts "========================================================="

      if length(tail) > 0 do
      bench_measure(plain_text,tail)
      else
        {:ok}
      end
    end



end
