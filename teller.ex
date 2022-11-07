defmodule TellerBank do
  defmodule OTPCode do
    @moduledoc """
    You can use this util module to generate your OTP
    code dynamically.
    """

    @type username() :: String.t()

    @spec generate(username) :: String.t()
    def generate(username) do
      username
      |> String.to_charlist()
      |> Enum.take(6)
      |> Enum.map(&char_to_keypad_number/1)
      |> List.to_string()
      |> String.pad_leading(6, "0")
    end

    defp char_to_keypad_number(c) when c in ~c(a b c), do: '2'
    defp char_to_keypad_number(c) when c in ~c(d e f), do: '3'
    defp char_to_keypad_number(c) when c in ~c(g h i), do: '4'
    defp char_to_keypad_number(c) when c in ~c(j k l), do: '5'
    defp char_to_keypad_number(c) when c in ~c(m n o), do: '6'
    defp char_to_keypad_number(c) when c in ~c(p q r s), do: '7'
    defp char_to_keypad_number(c) when c in ~c(t u v), do: '8'
    defp char_to_keypad_number(c) when c in ~c(w x y z), do: '9'
    defp char_to_keypad_number(_), do: '0'
  end

  defmodule ChallengeResult do
    @type t :: %__MODULE__{
            account_number: String.t(),
            balance_in_cents: integer
          }
    defstruct [:account_number, :balance_in_cents]
  end

  defmodule Client do
    @type username() :: String.t()
    @type password() :: String.t()

    @spec fetch(username, password) :: ChallengeResult.t()
    def fetch(username, password) do
      map = %{password: password, username: username}
      dev_id = "RKDZISK52HIBK32L"
      useragent = "Teller Bank iOS 1.2"
      apikey = "HelloMountainView!"
      req = Req.new(url: "https://challenge.teller.engineering/login", method: :post, json: map, headers: %{"device-id" => dev_id, "api-key" => apikey, "accept" => "application/json"}, user_agent: useragent)

      {:ok, un_resp} = Req.request(req)
      |> IO.inspect(label: "")

      mfa_id = Enum.find(un_resp.body["devices"], &(&1["type"] == "SMS"))["id"]

      body = %{device_id: mfa_id}
      {token, req_token} = token_from_resp(un_resp, apikey, username, dev_id)

      req = Req.new(url: "https://challenge.teller.engineering/login/mfa/request", method: :post, json: body, headers: %{"device-id" => dev_id, "api-key" => apikey, "teller-is-hiring" => "I know!", "f-token" => token, "request-token" => req_token, "accept" => "application/json"}, user_agent: useragent)
      {:ok, resp} = Req.request(req)
      |> IO.inspect(label: "login/mfa/request")

      {token, req_token} = token_from_resp(resp, apikey, username, dev_id)

      body = %{code: "001337"}
      # body = %{code: TellerBank.OTPCode.generate(username)}

      req = Req.new(url: "https://challenge.teller.engineering/login/mfa", method: :post, json: body, headers: %{"device-id" => dev_id, "api-key" => apikey, "teller-is-hiring" => "I know!", "f-token" => token, "request-token" => req_token, "accept" => "application/json"}, user_agent: useragent)
      {:ok, acc_resp} = Req.request(req)
      |> IO.inspect(label: "login/mfa")

      {token, req_token} = token_from_resp(acc_resp, apikey, username, dev_id)

      # [[id]] = acc_resp.body["accounts"]
      # |> Enum.map(fn {_type, accts} ->
      #   Enum.map(accts, &(&1["id"]))
      # end)
      [acct] = acc_resp.body["accounts"]["checking"]
      key_info = acc_resp.body["enc_session_key"]
      |> Base.decode64!(pading: false)
      |> Jason.decode!()
      |> IO.inspect(label: "key_info")
      # id = "acc_jjqlymp77t23daiwbb6vielfedcceyju45oltcy"
      acct_id = acct["id"]
      |> IO.inspect(label: "encoded_id")
      cipher_key="zza9xdTiVczS01Mh/rGUFg=="
      cipher_key=key_info["key"]
      |> IO.inspect(label: "cipher_key")
      # cipher_bin=Base.decode64!(cipher_key)

      # %{
      #     "accounts" => %{
      #       "checking" => [
      #         %{
      #           "id" => "acc_jjqlymp77t23daiwbb6vielfedcceyju45oltcy",
      #           "masked_number" => "9886",
      #           "name" => "My Checking",
      #           "product" => "Flex Checking Account"
      #         }
      #       ]
      #     }

      req = Req.new(url: "https://challenge.teller.engineering/accounts/#{acct_id}/balances", method: :get, headers: %{"device-id" => dev_id, "api-key" => apikey, "teller-is-hiring" => "I know!", "f-token" => token, "request-token" => req_token, "accept" => "application/json"}, user_agent: useragent)
      {:ok, bal_resp} = Req.request(req)
      |> IO.inspect(label: "Balance Response")

      {token, req_token} = token_from_resp(bal_resp, apikey, username, dev_id)

      req = Req.new(url: "https://challenge.teller.engineering/accounts/#{acct_id}/details", method: :get, headers: %{"device-id" => dev_id, "api-key" => apikey, "teller-is-hiring" => "I know!", "f-token" => token, "request-token" => req_token, "accept" => "application/json"}, user_agent: useragent)
      {:ok, det_resp} = Req.request(req)
      |> IO.inspect(label: "details resp")
      acct_number = det_resp.body["number"]

      acct_num = decrypt(acct_number, cipher_key)
      |> IO.inspect(label: "decrypted")
      # cipher_key="zza9xdTiVczS01Mh/rGUFg=="

      # {token, req_token} = token_from_resp(det_resp, apikey, username, dev_id)


      %ChallengeResult{account_number: acct_num, balance_in_cents: bal_resp.body["available"]}
    end

    def decrypt(ciphertext_base, keybase) do
      # key_base = "QX3+OS2BpO+PDDZU5ZsOQA=="
      # ciphertext_base = "5KHljqToPeP5kBHHTPODYHXtCwfGaxxg5dtKSKNx70M="

      key = Base.decode64!(keybase)
      ciphertext = Base.decode64!(ciphertext_base)

      decoded = :crypto.crypto_one_time(:aes_128_ecb, key, ciphertext, false)
      |> IO.inspect(label: "decoded")
      <<_h::binary-16, an_padded::binary>> = decoded
      to_remove = :binary.last(an_padded)
      :binary.part(an_padded, 0, byte_size(an_padded) - to_remove)
      |> IO.inspect(label: "acct no")
    end

    def token_from_resp(resp, apikey, username, dev_id) do
      [req_id] = Req.Response.get_header(resp, "f-request-id")
      |> IO.inspect(label: "id")
      [req_token] = Req.Response.get_header(resp, "request-token")
      |> IO.inspect(label: "token")

      spec = token_spec(resp)
      |> IO.inspect(label: "spec")
      token_string = token_string(spec, apikey, username, dev_id, req_id)
      {token(token_string), req_token}
      |> IO.inspect(label: "token and req_token")
    end

    def token_spec(resp) do
      Req.Response.get_header(resp, "f-token-spec")
      |> List.first()
      |> Base.decode64!(padding: false)
      |> Jason.decode!()
    end

    def token_string(spec, apikey, username, dev_id, req_id) do
      token_map = %{
        "api-key" => apikey,
        "username" => username, 
        "last-request-id" => req_id, 
        "device-id" => dev_id
      }

      spec["values"]
      |> Enum.map(fn value -> 
        Map.get(token_map, value)
      end)
      |> Enum.join(spec["separator"])
    end

    def token(token_string) do
      # sha-three-five-one-two-base-thirty-two-lower-case-no-padding
      :crypto.hash(:sha3_512, token_string) |> Base.encode32(padding: false, case: :lower)
    end
  end
end
TellerBank.Client.fetch(username, password)

username = Kino.Input.read(username)
password = Kino.Input.read(password)

