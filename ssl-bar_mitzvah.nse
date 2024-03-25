description = [[
Uses ssl-enum-ciphers to detect support for RC4 cipher suites and assess vulnerability to BAR MITZVAH.
]]

author = "M Attique"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln"}

local stdnse = require("stdnse")
local shortport = require("shortport")
local sslcert = require("sslcert")
local nmap = require("nmap")

-- Define port rule to use Nmap provided flags like -p for specifying ports
portrule = function(host, port)
  return nmap.has_port(host, port) and port.state == "open" and port.protocol == "tcp"
end

action = function(host, port)
    -- Run the ssl-enum-ciphers script
    local status, result = stdnse.run_script("ssl-enum-ciphers", host, port)
    if not status then
        return stdnse.format_output(true, "Error running ssl-enum-ciphers on port " .. port.number)
    end

    local rc4_found = false

    -- Parse the ssl-enum-ciphers output to look for RC4 cipher suites
    for _, cipher in ipairs(result) do
        if cipher.output:find("RC4") then
            rc4_found = true
            break
        end
    end

    -- ANSI color codes
    local red = "\27[31m"
    local green = "\27[32m"
    local reset = "\27[0m"

    -- Prepare the report based on findings
    if rc4_found then
        return stdnse.format_output(true, red .. "Vulnerable to BAR MITZVAH (RC4 cipher suites found)." .. reset)
    else
        return stdnse.format_output(true, green .. "Not Vulnerable to BAR MITZVAH (No RC4 cipher suites found)." .. reset)
    end
end
