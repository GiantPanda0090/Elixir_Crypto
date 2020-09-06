defmodule Cryptonetwork.Onetimepad do
  @moduledoc """
  Documentation for `Cryptonetwork`.
  """

  @doc """
  Hello world.

  ## Examples

      iex> Cryptonetwork.hello()
      :world

  """
use Bitwise
##Reference https://stackoverflow.com/questions/32001606/how-to-generate-a-random-url-safe-string-with-elixir
##          https://stackoverflow.com/questions/20829348/how-to-join-strings-in-elixir
@chars "ABCDEFGHIJKLMNOPQRSTUVWXYZ" |> String.split("")
def string_of_length(length) do
  Enum.join(Enum.take_random(@chars, length), "")
end

##=====================================================================================================================================

  ##excercise 1 +2
  ##native
  def one_time_encrypt(data,:native) do
    key = :crypto.strong_rand_bytes(String.length(data)) ##rand
    cipher = one_time_encrypt(:base64.encode(key), data,:native)
    %{status: :encrypt_native,key: key,cipher: cipher}
    end

    def one_time_encrypt(key, data,:native) do
      cipher = :crypto.crypto_one_time(:aes_128_ctr,key, <<0::128>>,data,true)
      %{status: :encrypt_native,key: key,cipher: cipher}
      end

  def one_time_decrypt(key,cipher, :native) do
    data = :crypto.crypto_one_time(:aes_128_ctr,key, <<0::128>>,cipher,false)
    %{status: :decrypt_native, data: data}
  end

  ##custom
  ##mod
  def encrypt_mod([data | tail_data],[key | tail_key],out,decode_key,true) do
    <<d::utf8>> =String.upcase(data)
    <<k::utf8>> = String.upcase(key)
    cipher =  Integer.mod(d+k, 26) + 65
    if Enum.count(tail_data) > 0 do
    encrypt_mod(tail_data,tail_key,[cipher| out],[k| decode_key],true)
    else
      {Enum.reverse([cipher| out]),Enum.reverse([k| decode_key])}
    end
  end

  def encrypt_mod([data | tail_data],[key | tail_key],out,decode_key,false) do
    <<d::utf8>> =String.upcase(data)
    <<k::utf8>> = String.upcase(key)
    cipher =  Integer.mod(d-k, 26) + 65
    if Enum.count(tail_data) > 0 do
      encrypt_mod(tail_data,tail_key,[cipher| out],[k| decode_key],false)
      else
        {Enum.reverse([cipher| out]),Enum.reverse([k| decode_key])}
      end
    end

    def hack_mod([data | tail_data],[cipher | tail_cipher],out) do
      <<d::utf8>> =String.upcase(data)
      <<c::utf8>> = String.upcase(cipher)

      key =  Integer.mod(c-d, 26) + 65
        if Enum.count(tail_data) > 0 do
        hack_mod(tail_data,tail_cipher,[key| out])
        else
          Enum.reverse([key| out])
        end
      end

##mod main
  def one_time_encrypt(data,:custom_mod)  do
    key = string_of_length(String.length(data)) ##rand
    one_time_encrypt( key,data,:custom_mod)
  end

  def one_time_encrypt(key,data,:custom_mod) do
    split_data = String.graphemes(to_string data)
    split_key = String.graphemes(to_string key)
    {cipher,decode_key}=encrypt_mod(split_data,split_key,[],[],true)
    %{status: :encrypt_custom_mod, key: decode_key,cipher: cipher}
  end

  def one_time_decrypt(key,data,:custom_mod) do
    split_data = String.graphemes(to_string data)
    split_key = String.graphemes(to_string key)
    {data,decode_key}=encrypt_mod(split_data,split_key,[],[],false)
      %{status: :decrypt_custom_mod, key: decode_key,plain_text: data}
  end


##xor
def encrypt_xor([data | tail_data],[key | tail_key],out,decode_key,true) do
  <<d::utf8>> =String.upcase(data)
  <<k::utf8>> = String.upcase(key)
  cipher =  d ^^^ k
  #cipher = c + 65
  if Enum.count(tail_data) > 0 do
  encrypt_xor(tail_data,tail_key,[cipher| out],[k| decode_key],true)
  else
    {Enum.reverse([cipher| out]), Enum.reverse([k| decode_key])}
  end
end

def encrypt_xor([cipher | tail_cipher],[key | tail_key],out,decode_key,false) do
  <<c::utf8>> =String.upcase(cipher)
  <<k::utf8>> = String.upcase(key)
  #c_d = c-65
  data =  c ^^^ k
  if Enum.count(tail_cipher) > 0 do
  encrypt_xor(tail_cipher,tail_key,[data| out],[k| decode_key],false)
  else
    {Enum.reverse([data| out]),Enum.reverse([k| decode_key])}
  end
end

def hack_xor([data | tail_data],[cipher | tail_cipher],out) do
  <<d::utf8>> =String.upcase(data)
  <<c::utf8>> = String.upcase(cipher)
  #c_d = c-65
  k =  d ^^^ c
  if Enum.count(tail_data) > 0 do
    hack_xor(tail_data,tail_cipher,[k| out])
  else
    Enum.reverse([k| out])
  end
end


##xor main
  def one_time_encrypt(data,:custom_xor) do
    key = string_of_length(String.length(data)) ##rand
    one_time_encrypt(key,data,:custom_xor)
  end

  def one_time_encrypt(key,data,:custom_xor) do
    split_data = String.graphemes(to_string data)
    split_key = String.graphemes(to_string key)
    {cipher,decode_key}=encrypt_xor(split_data,split_key,[],[],true)
    %{status: :encrypt_custom_xor, key: decode_key,cipher: cipher}
  end

  def one_time_decrypt(key,data,:custom_xor) do
    split_data = String.graphemes(to_string data)
    split_key = String.graphemes(to_string key)
    {data,decode_key}=encrypt_xor(split_data,split_key,[],[],false)
    %{status: :decrypt_custom_xor, key: decode_key,plain_text: String.upcase(to_string data)}
  end


##hack
  def hack_key(data,cipher,:custom_mod) do
    split_data = String.graphemes(to_string data)
    split_cipher = String.graphemes(to_string cipher)
    %{status: :hack_mod, plain_text: data,cipher: cipher, key: hack_mod(split_data,split_cipher,[])}
    end

  def hack_key(data,cipher,:custom_xor) do
      split_cipher = String.graphemes(to_string cipher)
      split_data = String.graphemes(to_string data)
      %{status: :hack_xor, plain_text: data,cipher: cipher, key: hack_xor(split_data,split_cipher,[])}
      end


end
