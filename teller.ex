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
      dev_id = "JFANVAI3KUUQ77ZZ"
      useragent = "Teller Bank iOS 1.0"
      apikey = "good-luck-at-the-teller-quiz!"
      req = Req.new(url: "https://challenge.teller.engineering/login", method: :post, json: map, headers: %{"device-id" => dev_id, "api-key" => apikey, "accept" => "application/json"}, user_agent: useragent)

      {:ok, un_resp} = Req.request(req)

      mfa_id = Enum.find(un_resp.body["mfa_devices"], &(&1["type"] == "SMS"))["id"]

      body = %{device_id: mfa_id}
      {token, req_token} = token_from_resp(un_resp, apikey, username, dev_id)

      req = Req.new(url: "https://challenge.teller.engineering/login/mfa/request", method: :post, json: body, headers: %{"device-id" => dev_id, "api-key" => apikey, "teller-is-hiring" => "I know!", "f-token" => token, "request-token" => req_token, "accept" => "application/json"}, user_agent: useragent)
      {:ok, resp} = Req.request(req)

      {token, req_token} = token_from_resp(resp, apikey, username, dev_id)

      body = %{code: TellerBank.OTPCode.generate(username)}

      req = Req.new(url: "https://challenge.teller.engineering/login/mfa", method: :post, json: body, headers: %{"device-id" => dev_id, "api-key" => apikey, "teller-is-hiring" => "I know!", "f-token" => token, "request-token" => req_token, "accept" => "application/json"}, user_agent: useragent)
      {:ok, acc_resp} = Req.request(req)

      {token, req_token} = token_from_resp(acc_resp, apikey, username, dev_id)

      [[id]] = acc_resp.body["accounts"]
      |> Enum.map(fn {_type, accts} -> 
        Enum.map(accts, &(&1["id"]))        
      end)

      req = Req.new(url: "https://challenge.teller.engineering/accounts/#{id}/details", method: :get, headers: %{"device-id" => dev_id, "api-key" => apikey, "teller-is-hiring" => "I know!", "f-token" => token, "request-token" => req_token, "accept" => "application/json"}, user_agent: useragent)
      {:ok, det_resp} = Req.request(req)
      acct_number = det_resp.body["number"]
      {token, req_token} = token_from_resp(det_resp, apikey, username, dev_id)

      req = Req.new(url: "https://challenge.teller.engineering/accounts/#{id}/balances", method: :get, headers: %{"device-id" => dev_id, "api-key" => apikey, "teller-is-hiring" => "I know!", "f-token" => token, "request-token" => req_token, "accept" => "application/json"}, user_agent: useragent)
      {:ok, bal_resp} = Req.request(req)
      |> IO.inspect(label: "Balance Response")

      %ChallengeResult{account_number: acct_number, balance_in_cents: bal_resp.body["available"]}
    end

    defp token_from_resp(resp, apikey, username, dev_id) do
      [req_id] = Req.Response.get_header(resp, "f-request-id")
      [req_token] = Req.Response.get_header(resp, "request-token")

      spec = token_spec(resp)
      token_string = token_string(spec, apikey, username, dev_id, req_id)
      {token(token_string), req_token}
    end

    defp token_spec(resp) do
      Req.Response.get_header(resp, "f-token-spec")
      |> List.first()
      |> Base.decode64!()
      |> Jason.decode!()
    end

    defp token_string(spec, apikey, username, dev_id, req_id) do
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

    defp token(token_string) do
      :crypto.hash(:sha256, token_string) |> Base.encode64(padding: false)
    end
  end
end

username = Kino.Input.read(username)
password = Kino.Input.read(password)

TellerBank.Client.fetch(username, password)
