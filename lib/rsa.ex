defmodule Cryptonetwork.Rsa do

  import Math

  def main(p,q,text) do
  plain_text = to_charlist text
  {public,private} = get_key(p,q) ##public/private key
  cipher = rsa_encrypt(plain_text, public)
  plain = rsa_decrypt(cipher,private)
  %{plain_text: plain_text,plain_text_afterdecrypt: plain,cipher: cipher}
  end

  def main(p,q,e, text) do
    plain_text = to_charlist text
    {public,private} = get_key(p,q,e) ##public/private key
    cipher = rsa_encrypt(plain_text, public)
    plain = rsa_decrypt(cipher,private)
    %{plain_text: plain_text,plain_text_afterdecrypt: plain,cipher: cipher}
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
  plain_text = rsa_public_decrypt(cipher,[:binary.encode_unsigned(n),d],[])
  #plain_text_decode = binary_to_list(plain_text)
  end


  def rsa_private_encrypt([h|t],[<<x::bits-size(8), a::binary>> ,e],cipher) do
    <<n>> = x
    if h >= n do
      raise  ArgumentError, message: "Include lettters bigger than N, N = " <> to_string n
    else
    ciph = Integer.mod(Math.pow(h,e),n)
    if length(t) > 0 do
    rsa_private_encrypt(t,[a,e],[ciph|cipher])
    else
      Enum.reverse([ciph|cipher])
    end
  end
  end

  def rsa_public_decrypt([h|t],[<<x::bits-size(8), a::binary>> ,d],plain_text) do
    <<n>> = x

    if h >= n do
      raise  ArgumentError, message: "Include lettters bigger than N, N = " <> to_string n
    else
    plain = Integer.mod(Math.pow(h,d),n)
    if length(t) > 0 do
      rsa_public_decrypt(t,[a,d],[plain|plain_text])
      else
        Enum.reverse([plain|plain_text])
      end
    end
  end

  ##Reference https://hexdocs.pm/ex_crypto/readme.html
  def excrypto_encrypt(plain_text) do
    {pem, 0} = System.cmd "openssl", ["genrsa","2048"]
    key = pem    |> :public_key.pem_decode |> List.first |> :public_key.pem_entry_decode
    {:RSAPrivateKey, :'two-prime', n , e, d, p, q, _e1, _e2, _c, _other} =key
       enc = :crypto.public_encrypt(:rsa, plain_text, [e,n], :rsa_pkcs1_padding)
       out_native = :base64.encode_to_string(enc)
       IO.puts "Native complete. Output string: " <> to_string out_native
       out_custom = main(p,q,plain_text)
       %{native: out_native, custom: out_custom}
       IO.puts "Custom complete. Output string: " <> to_string out_custom

    end

end
