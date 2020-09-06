defmodule Cryptonetwork.Rsa do

  import Math

  def main(p,q,plain_text) do
  {public,private} = get_key(p,q) ##public/private key
  cipher = rsa_encrypt(plain_text, public)
  plain = rsa_decrypt(cipher,private)
  %{plain_text: plain_text,plain_text_afterdecrypt: plain,cipher: cipher}
  end

  def main(p,q,e,plain_text) do
    {public,private} = get_key(p,q,e) ##public/private key
    cipher = rsa_encrypt(plain_text, public)
    plain = rsa_decrypt(cipher,private)
    %{plain_text: plain_text,plain_text_afterdecrypt: plain,cipher: cipher}
    end

  def get_e(w,e) do
    if Integer.gcd(w,e) != 1 do
      get_e(w,e-1)
    else
      e
    end
  end

  def get_key(p,q,e) do
    n=p*q
    w=(p-1)*(q-1)
    {:ok, d} = Math.mod_inv(e, w)
    {{n,e},{n,d}}
  end

  def get_key(p,q) do
    n=p*q
    w=(p-1)*(q-1)
    e = get_e(w,w)
    {:ok, d} = Math.mod_inv(e, w)
    {{n,e},{n,d}}
  end

  ## Referenece http://erlang.org/pipermail/erlang-questions/2009-June/044861.html
  def rsa_encrypt(plain_text,{n,e}) do
   rsa_private_encrypt(plain_text,[n,e],[])
  end

  def rsa_decrypt(cipher,{n,d}) do
  plain_text = rsa_public_decrypt(cipher,[n,d],[])
  #plain_text_decode = binary_to_list(plain_text)
  end


  def rsa_private_encrypt([h|t],[n,e],cipher) do
    if h >= n do
      raise  ArgumentError, message: "Include lettters bigger than N, N = " <> to_string n
    else
    ciph = Integer.mod(Math.pow(h,e),n)
    if length(t) > 0 do
    rsa_private_encrypt(t,[n,e],[ciph|cipher])
    else
      Enum.reverse([ciph|cipher])
    end
  end
  end

  def rsa_public_decrypt([h|t],[n,d],plain_text) do
    if h >= n do
      raise  ArgumentError, message: "Include lettters bigger than N, N = " <> to_string n
    else
    plain = Integer.mod(Math.pow(h,d),n)
    if length(t) > 0 do
      rsa_public_decrypt(t,[n,d],[plain|plain_text])
      else
        Enum.reverse([plain|plain_text])
      end
    end
  end





end
