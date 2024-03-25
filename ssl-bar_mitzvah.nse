description = [[
Detects support for RC4 cipher suites to assess vulnerability to BAR MITZVAH.
Reports on every scanned host whether it's vulnerable.
]]

author = "M Attique"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln"}

local shortport = require "shortport"
local stdnse = require "stdnse"
local sslcert = require "sslcert"
local table = require "table"
local tls = require "tls"

portrule = shortport.ssl

action = function(host, port)
    -- Leverage ssl-enum-ciphers script directly for cipher suite enumeration
    local status, result = stdnse.run_script("ssl-enum-ciphers", host, port)
    if not status or not result then
        return stdnse.format_output(false, "Failed to run ssl-enum-ciphers or no data returned.")
    end

    -- Look for RC4 ciphers in the results
    local vulnerable = false
    for _, cipher in ipairs(result.ciphers) do
        if cipher.name:find("RC4") then
            vulnerable = true
            break
        end
    end

    -- ANSI color codes for terminal output (note: might not work in all output formats)
    local red = "\27[31m"
    local green = "\27[32m"
    local reset = "\27[0m"
    local message = vulnerable and (red .. "Vulnerable to BAR MITZVAH (RC4 cipher suites found)." .. reset) or (green .. "Not Vulnerable to BAR MITZVAH (No RC4 cipher suites found)." .. reset)

    return stdnse.format_output(true, message)
end
