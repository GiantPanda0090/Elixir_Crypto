defmodule Cryptonetwork.Diffkeyex do

  import Math
  ## TODO multithread optimization needed o2
  def pick_g(p,g,pow,out) do
    ##[2,(g-1)]^[0,g-2] mod g
    r = Integer.mod(Math.pow(g,pow), p)
    if pow < p-2 do
      pick_g(p,g,pow+1,[r | out])
    else
      list = Enum.uniq(Enum.sort([r|out]))
      list_index = Enum.with_index(list)
       result = list_checker(list_index,true)
      if result == false and g < p-1 do
        pick_g(p,g+1,0,[r | out])
      else
        {p,g}
      end
    end
  end

  def list_checker([{item,i} | tail],result) do
    if (length(tail) > 1) and result do

    list_checker(tail,((item - 1) == i) or result)
    else
      (item - 1) == i and result
    end
  end


  def gen_message(p,m) do
    {p,g} = pick_g(p,2,0,[])
    IO.inspect %{p: p,g: g, m: m}
    key_encry = Integer.mod(Math.pow(g,m),p)
    {key_encry,p,g}
  end

  def open_message(rec_msg,send_msg,p,g) do
    key = Integer.mod(Math.pow(Math.pow(g,rec_msg),send_msg),p)
  end

  def user({msg,p,g},username) do
      receive do
        {:recv_pid, receiver_pid} -> send receiver_pid,{:ok, msg,self(),username}
        {:ok,rec_msg,pid,sender} -> key = open_message(rec_msg,msg,p,g)
                         IO.puts username <> ": receive key from - " <> to_string sender <> " the key content is: " <> to_string key
      end
      user({msg,p,g},username)
  end

  def user_gen(p,m,username) do
    {msg,p,g}= gen_message(p,m)
    spawn(fn ->
      user({msg,p,g},username)
    end)
  end

  def demo(p,m) do
    user_1=Cryptonetwork.Diffkeyex.user_gen(p,m,"Alice")
    user_2= Cryptonetwork.Diffkeyex.user_gen(p,m,"Bob")
    send user_2, {:recv_pid, user_1}
    send user_1, {:recv_pid, user_2}
    send user_2, {:recv_pid, user_1}
    send user_1, {:recv_pid, user_2}
  end


end
