description = [[
Detects if the target hosts are using RC4 cipher suites, indicating potential vulnerability to the BAR MITZVAH vulnerability.
]]

author = "Attique"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

portrule = function(host, port)
  -- Allows any port specified by -p option; assumes SSL/TLS can run on any port.
  return sslcert.isPortSupported(port)
end

action = function(host, port)
  local status, result = sslcert.getCipherSuites(host, port)
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
