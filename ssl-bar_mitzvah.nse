description = [[
Detects if the target hosts are using RC4 cipher suites, indicating potential vulnerability to the BAR MITZVAH vulnerability.
]]

author = "M-Attique"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

-- Import the tls library
local tls = require("tls")

portrule = function(host, port)
  -- Check if the port is open and selected by the user with the -p option
  return port.state == "open"
end

action = function(host, port)
  local status, result = tls.getCipherSuites(host, port)
  if not status then
    return "Failed to retrieve SSL cipher suites."
  end

  local vulnerable = false
  local rc4_ciphers = {}

  for _, cipher in ipairs(result) do
    if cipher.name:match("RC4") then
      vulnerable = true
      table.insert(rc4_ciphers, cipher.name)
    end
  end

  if vulnerable then
    return ("Host is potentially vulnerable to BAR MITZVAH (using RC4 ciphers): \n - %s"):format(table.concat(rc4_ciphers, "\n - "))
  else
    return "Host does not appear to be vulnerable to BAR MITZVAH (no RC4 ciphers found)."
  end
end
